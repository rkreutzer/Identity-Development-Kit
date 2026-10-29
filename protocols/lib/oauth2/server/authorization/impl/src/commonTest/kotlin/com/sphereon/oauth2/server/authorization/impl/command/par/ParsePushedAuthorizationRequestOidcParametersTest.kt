/*
 * Copyright 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.sphereon.oauth2.server.authorization.impl.command.par

import com.sphereon.oauth2.common.model.ClientAuthenticationConfig
import com.sphereon.oauth2.server.authorization.command.ParsePushedAuthorizationRequestArgs
import com.sphereon.oauth2.server.authorization.impl.command.jar.StubVerifyRequestObjectCommand
import com.sphereon.oauth2.server.authorization.impl.testutil.OAuth2ServerTestContext
import com.sphereon.oauth2.server.authorization.impl.testutil.StubOAuth2ServersConfigProvider
import com.sphereon.oauth2.server.authorization.model.Prompt
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * A pushed request keeps the OpenID Connect request parameters (OpenID Connect Core 1.0 §3.1.2.1), as the
 * Authorization Endpoint does. The authorization code, and so the ID Token, take them from the pushed request: a
 * dropped `nonce` produces an ID Token without the nonce the client sent, which the client must refuse.
 */
class ParsePushedAuthorizationRequestOidcParametersTest {
    private val ctx = OAuth2ServerTestContext("parse-par-oidc-parameters-test", this)

    @Test
    fun pushedRequestKeepsTheOpenIdConnectRequestParameters() =
        runTest {
            val command =
                ParsePushedAuthorizationRequestCommandImpl(
                    execution = ctx.execution,
                    verifyRequestObjectCommand = StubVerifyRequestObjectCommand(ctx.execution),
                    serversConfigProvider = StubOAuth2ServersConfigProvider(),
                )
            val body =
                mapOf(
                    "client_id" to "rp",
                    "response_type" to "code",
                    "redirect_uri" to "https://rp.example/cb",
                    "scope" to "openid profile",
                    "state" to "s",
                    "nonce" to "n-1",
                    "response_mode" to "query",
                    "prompt" to "login consent",
                    "max_age" to "300",
                    "login_hint" to "alice",
                    "id_token_hint" to "hint.jwt.value",
                    "acr_values" to "urn:acr:1 urn:acr:2",
                    "ui_locales" to "nl en",
                    "display" to "page",
                    "claims" to """{"id_token":{"email":null}}""",
                ).mapValues { listOf(it.value) }

            val result = command.execute(ParsePushedAuthorizationRequestArgs(requestBody = body, clientAuthentication = ClientAuthenticationConfig.None(clientId = "rp")))

            assertTrue(result.isOk, "parse failed: ${if (result.isErr) result.error.message.defaultMessage else ""}")
            val parsed = result.value
            assertEquals("n-1", parsed.nonce)
            assertEquals("query", parsed.responseMode)
            assertEquals(setOf(Prompt.LOGIN, Prompt.CONSENT), parsed.prompt)
            assertEquals(300, parsed.maxAge)
            assertEquals("alice", parsed.loginHint)
            assertEquals("hint.jwt.value", parsed.idTokenHint)
            assertEquals(listOf("urn:acr:1", "urn:acr:2"), parsed.acrValues)
            assertEquals(listOf("nl", "en"), parsed.uiLocales)
            assertEquals("page", parsed.display)
            assertEquals(buildJsonObject { put("id_token", buildJsonObject { put("email", kotlinx.serialization.json.JsonNull) }) }, parsed.claims)
        }

    @Test
    fun pushedRequestRefusesAMalformedMaxAgeOrClaims() =
        runTest {
            val command =
                ParsePushedAuthorizationRequestCommandImpl(
                    execution = ctx.execution,
                    verifyRequestObjectCommand = StubVerifyRequestObjectCommand(ctx.execution),
                    serversConfigProvider = StubOAuth2ServersConfigProvider(),
                )
            fun body(extra: Pair<String, String>) =
                mapOf("client_id" to "rp", "response_type" to "code", "redirect_uri" to "https://rp.example/cb", extra).mapValues { listOf(it.value) }
            for (bad in listOf("max_age" to "-1", "max_age" to "soon", "claims" to "[1]", "claims" to "{not json")) {
                val result = command.execute(ParsePushedAuthorizationRequestArgs(requestBody = body(bad), clientAuthentication = ClientAuthenticationConfig.None(clientId = "rp")))
                assertTrue(result.isErr, "expected $bad to be refused")
                assertEquals("invalid_request", result.error.code)
            }
        }
}
