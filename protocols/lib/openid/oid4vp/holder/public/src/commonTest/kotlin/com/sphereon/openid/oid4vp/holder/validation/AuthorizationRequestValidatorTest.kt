/* Copyright 2026 Sphereon International B.V. SPDX-License-Identifier: Apache-2.0 */
package com.sphereon.openid.oid4vp.holder.validation

import com.sphereon.oauth2.common.model.AuthorizationRequest
import io.konform.validation.Invalid
import io.konform.validation.Valid
import kotlinx.serialization.json.JsonPrimitive
import kotlin.test.Test
import kotlin.test.assertTrue

class AuthorizationRequestValidatorTest {
    private fun request(mode: String = "direct_post") = AuthorizationRequest(
        clientId = "test-client", responseType = "vp_token", responseMode = mode,
        nonce = "a-._~09AZaz", state = "state",
        additionalParameters = mapOf("response_uri" to JsonPrimitive("https://verifier.example/response")),
    )

    @Test
    fun directPostModesRejectRedirectUriAndRequireResponseUri() {
        for (mode in listOf("direct_post", "direct_post.jwt")) {
            assertTrue(validateOid4vpAuthorizationRequest(request(mode)) is Valid)
            assertTrue(validateOid4vpAuthorizationRequest(request(mode).copy(redirectUri = "https://verifier.example/redirect")) is Invalid)
            assertTrue(validateOid4vpAuthorizationRequest(request(mode).copy(additionalParameters = emptyMap())) is Invalid)
        }
    }

    @Test
    fun nonceIsRequiredAndUrlSafeWithoutAnInventedMinimumLength() {
        for (nonce in listOf(null, "", "with space", "non_ascii_é", "base64+slash/")) {
            assertTrue(validateOid4vpAuthorizationRequest(request().copy(nonce = nonce)) is Invalid)
        }
        assertTrue(validateOid4vpAuthorizationRequest(request().copy(nonce = "a")) is Valid)
    }

    @Test
    fun responseModeIsRequiredAndStateMustBeUrlSafe() {
        assertTrue(validateOid4vpAuthorizationRequest(request().copy(responseMode = null)) is Invalid)
        assertTrue(validateOid4vpAuthorizationRequest(request().copy(state = "with space")) is Invalid)
        assertTrue(validateOid4vpAuthorizationRequest(request().copy(state = "AZaz09-._~")) is Valid)
    }
}
