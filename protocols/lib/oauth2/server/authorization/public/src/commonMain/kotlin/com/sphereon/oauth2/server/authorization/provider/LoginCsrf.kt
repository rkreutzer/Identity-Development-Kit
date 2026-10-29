/*
 * © 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

package com.sphereon.oauth2.server.authorization.provider

/**
 * Supplies a symmetric secret to HMAC-based login CSRF tokenizers. A deployment using this
 * implementation must resolve the key through its configured secret authority.
 *
 * Multi-instance deployments MUST bind a shared secret because each instance's default key is
 * independent.
 */
interface LoginCsrfKeyProvider {
    /** Return the current HMAC key bytes. Must be at least 16 bytes; 32 strongly recommended. */
    fun keyBytes(): ByteArray
}

/**
 * Mints and verifies an opaque `(tab_id, session_code)` CSRF tuple bound to a `session_id` on the
 * login form. Defends against capability-URL leak: an attacker who learns
 * `/login?session_id=<sid>` from a referrer log or browser history cannot mint or discover
 * a valid tuple for that session.
 *
 * Wire shape on the rendered form:
 *  - hidden `session_id` : opaque pending-auth-session id, already public.
 *  - hidden `tab_id`     : random, freshly minted per render.
 *  - hidden `session_code` : opaque verifier value bound to the session and tab.
 *
 * The cookie binding (separate cookie holding the tab_id) is enforced at the HTTP layer; this
 * contract is the cryptographic core.
 */
interface LoginCsrfTokenizer {
    /**
     * Mint a fresh `(tab_id, session_code)` for [sessionId]. The caller embeds both in the
     * rendered form's hidden inputs and writes the tab_id to a `oidc_login_csrf` cookie so
     * the POST handler can confirm both halves were present for the same browser session.
     */
    suspend fun mint(sessionId: String): LoginCsrfToken

    /**
     * Verify the tuple submitted with [sessionId]. Secret verifier comparisons must be
     * constant-time. A durable single-use implementation consumes a matching tuple atomically
     * with verification of the exact live pending authorization context. Invalid tuples must
     * not consume valid state; storage failure must never succeed.
     */
    suspend fun verify(
        sessionId: String,
        tabId: String,
        sessionCode: String,
    ): Boolean
}

/**
 * Output of [LoginCsrfTokenizer.mint]. Both fields are wire-visible in the rendered form;
 * the [tabId] is also written to the `oidc_login_csrf` cookie for the cookie-binding half
 * of the defense.
 */
data class LoginCsrfToken(
    val tabId: String,
    val sessionCode: String,
)
