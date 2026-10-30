/* Copyright 2026 Sphereon International B.V. SPDX-License-Identifier: Apache-2.0 */
package com.sphereon.oauth2.common.jarm

import com.sphereon.core.api.session.asCoreApiServiceGraph
import com.sphereon.crypto.core.KeyVisibility
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.crypto.jose.jwe.DecryptJweArgs
import com.sphereon.crypto.jose.jwe.JweCompact
import com.sphereon.crypto.jose.jwe.JweServiceImpl
import com.sphereon.crypto.jose.jws.JwtServiceImpl
import com.sphereon.crypto.resolution.managed.ManagedOptsKeyInfo
import com.sphereon.oauth2.common.testutil.Oauth2CommonTestContext
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class CreateJarmErrorResponseTest {
    @Test
    fun unsignedEncryptedErrorDoesNotInventStandardJwtClaimsOrRequireIssuer() = runTest {
        val context = Oauth2CommonTestContext("jarm-error-envelope", this@CreateJarmErrorResponseTest)
        val jwe = (context.session.graph as JweServiceImpl.Graph).jweService
        val command = CreateJarmResponseCommandImpl(
            context.session.asCoreApiServiceGraph().serviceExecution,
            (context.session.graph as JwtServiceImpl.Graph).jwtService, jwe,
        )
        val pair = context.keyManagerService.generateKeyAsync(alg = SignatureAlgorithm.ECDSA_SHA256)
        val key = ManagedOptsKeyInfo(identifier = pair.joseToManagedKeyInfo(KeyVisibility.PRIVATE))
        val payload = buildJsonObject { put("error", JsonPrimitive("invalid_request")) }
        val result = command.execute(CreateJarmResponseArgs(
            responseParameters = payload, state = "original-state", audience = "verifier",
            encryptionRecipient = key, jarmConfig = JarmConfig.encrypted("ECDH-ES"), appendStandardJwtClaims = false,
        )).getOrThrow()
        val decoded = jwe.decryptJwe(DecryptJweArgs(jwe = JweCompact.parse(result.jarmJwt), decryptor = key)).getOrThrow()
        assertEquals(buildJsonObject {
            put("error", JsonPrimitive("invalid_request"))
            put("state", JsonPrimitive("original-state"))
        }, Json.parseToJsonElement(requireNotNull(decoded.plaintext).decodeToString()))
        assertEquals(JarmMode.ENCRYPTED, result.mode)
        assertTrue(command.execute(CreateJarmResponseArgs(
            responseParameters = payload, audience = "verifier", signingKey = key,
            jarmConfig = JarmConfig.signed(),
        )).isErr)
    }
}
