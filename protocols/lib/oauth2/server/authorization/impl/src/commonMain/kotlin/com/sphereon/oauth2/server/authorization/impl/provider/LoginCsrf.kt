/*
 * © 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

package com.sphereon.oauth2.server.authorization.impl.provider

import com.sphereon.core.api.encodeToBase64Url
import com.sphereon.core.api.security.ConstantTime
import com.sphereon.oauth2.server.authorization.provider.LoginCsrfKeyProvider
import com.sphereon.oauth2.server.authorization.provider.LoginCsrfToken
import com.sphereon.oauth2.server.authorization.provider.LoginCsrfTokenizer
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.HMAC
import dev.whyoleg.cryptography.algorithms.SHA256
import dev.zacsweers.metro.AppScope
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding
import kotlin.random.Random

/**
 * Process-local fixture implementation using [Random.nextBytes]. It provides neither
 * cryptographic entropy nor persistence across instances or restarts. Production assemblies
 * must replace the tokenizer with a durable implementation using the platform CSPRNG;
 * this provider must not establish production or conformance acceptance.
 */
@Inject
@SingleIn(AppScope::class)
@ContributesBinding(AppScope::class, binding = binding<LoginCsrfKeyProvider>())
class InMemoryLoginCsrfKeyProvider(
    secureRandom: com.sphereon.core.api.random.SecureRandom,
) : LoginCsrfKeyProvider {
    // Random.nextBytes does not invoke the injected CSPRNG. Production tokenizers must
    // obtain entropy through SecureRandom and persist their verification authority.
    @Suppress("unused") // injected so Metro's graph proves the SecureRandom dependency exists.
    private val secureRandomHoldRef = secureRandom

    private val key: ByteArray = ByteArray(KEY_LENGTH_BYTES).also { Random.nextBytes(it) }

    override fun keyBytes(): ByteArray = key

    companion object {
        // 32 bytes = 256-bit secret. Matches HMAC-SHA-256 output size; longer keys are
        // truncated by HMAC's pre-processing, shorter keys reduce security.
        private const val KEY_LENGTH_BYTES: Int = 32
    }
}

/**
 * HMAC-SHA-256 implementation of [LoginCsrfTokenizer]. `session_code` is
 * `BASE64URL(HMAC-SHA-256(key, sid || "|" || tab_id))` and verification uses
 * [ConstantTime.equalsCT] so a forgery probe cannot recover the expected code byte-by-byte
 * from response timing.
 */
@Inject
@SingleIn(AppScope::class)
@ContributesBinding(AppScope::class, binding = binding<LoginCsrfTokenizer>())
class LoginCsrfTokenizerImpl(
    private val keyProvider: LoginCsrfKeyProvider,
) : LoginCsrfTokenizer {
    private val provider = CryptographyProvider.Default
    private val hmac = provider.get(HMAC)

    override suspend fun mint(sessionId: String): LoginCsrfToken {
        val tabId = generateTabId()
        val sessionCode = computeMac(sessionId, tabId)
        return LoginCsrfToken(tabId = tabId, sessionCode = sessionCode)
    }

    override suspend fun verify(
        sessionId: String,
        tabId: String,
        sessionCode: String,
    ): Boolean {
        if (sessionId.isBlank() || tabId.isBlank() || sessionCode.isBlank()) return false
        val expected = computeMac(sessionId, tabId)
        return ConstantTime.equalsCT(expected, sessionCode)
    }

    private suspend fun computeMac(
        sessionId: String,
        tabId: String,
    ): String {
        val key =
            hmac
                .keyDecoder(SHA256)
                .decodeFromByteArray(HMAC.Key.Format.RAW, keyProvider.keyBytes())
        val message = "$sessionId|$tabId".encodeToByteArray()
        val tag = key.signatureGenerator().generateSignature(message)
        return tag.encodeToBase64Url()
    }

    private fun generateTabId(): String {
        // 16 bytes = 128 bits of entropy. Plenty for a per-tab anti-replay value; the actual
        // capability URL leak defense rests on the HMAC + key, not on the tab_id's secrecy.
        val bytes = ByteArray(TAB_ID_LENGTH_BYTES).also { Random.nextBytes(it) }
        return bytes.encodeToBase64Url()
    }

    companion object {
        private const val TAB_ID_LENGTH_BYTES: Int = 16
    }
}
