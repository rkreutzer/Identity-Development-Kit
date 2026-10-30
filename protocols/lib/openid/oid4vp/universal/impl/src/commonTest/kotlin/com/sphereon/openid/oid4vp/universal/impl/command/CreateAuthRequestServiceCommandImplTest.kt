/*
 * © 2026 Sphereon International B.V.
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

package com.sphereon.openid.oid4vp.universal.impl.command

import com.sphereon.core.api.Err
import com.sphereon.core.api.Ok
import com.sphereon.core.api.error.IdkError
import com.sphereon.oauth2.common.model.AuthorizationRequest
import com.sphereon.openid.oid4vp.dcql.DcqlCredentialQuery
import com.sphereon.openid.oid4vp.dcql.DcqlQuery
import com.sphereon.openid.oid4vp.dcql.sdJwtVcMeta
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSession
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSessionCallbackConfig
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSessionStatus
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.assertNotEquals
import com.sphereon.openid.oid4vp.verifier.config.MutableOid4vpVerifierInstanceIdProvider
import kotlinx.coroutines.test.runTest

class CreateAuthRequestServiceCommandImplTest {
    @Test
    fun claimedOperationStateUsesUrlSafeAsciiAndKeepsItsStableDistinctBinding() {
        val state = claimedAuthorizationState("operation-a")
        assertTrue(state.matches(Regex("^[A-Za-z0-9._~-]+$")), "OID4VP state must use URL-safe ASCII")
        assertEquals(state, claimedAuthorizationState("operation-a"))
        assertNotEquals(state, claimedAuthorizationState("operation-b"))
    }
    @Test
    fun commandSelectsRequestedInstanceAndRestoresItAfterFailure() = runTest {
        val provider = TestInstanceProvider()
        val result = withRequestedVerifierInstance<Unit>(provider, "verifier-a") {
            assertEquals("verifier-a", provider.currentInstanceId())
            Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "downstream refused"))
        }
        assertIs<Err<IdkError>>(result)
        assertNull(provider.currentInstanceId())
    }

    @Test
    fun commandCannotOverrideRoutedVerifierAndPreservesMatchingRoute() = runTest {
        val provider = TestInstanceProvider("verifier-a")
        val refused = withRequestedVerifierInstance<Unit>(provider, "verifier-b") {
            error("A conflicting instance must not execute")
        }
        assertIs<Err<IdkError>>(refused)
        assertEquals("verifier-a", provider.currentInstanceId())
        assertEquals("accepted", assertIs<Ok<String>>(withRequestedVerifierInstance(provider, "verifier-a") { Ok("accepted") }).value)
        assertEquals("verifier-a", provider.currentInstanceId())
    }

    @Test
    fun commandKeepsLegacyDefaultAndRestoresInstanceAfterException() = runTest {
        val provider = TestInstanceProvider()
        withRequestedVerifierInstance(provider, null) { assertNull(provider.currentInstanceId()); Ok(Unit) }
        try {
            withRequestedVerifierInstance<Unit>(provider, "verifier-a") { error("downstream failure") }
        } catch (_: IllegalStateException) {
            // The operation failed, but the request scope must still be restored.
        }
        assertNull(provider.currentInstanceId())
    }

    private class TestInstanceProvider(private var id: String? = null) : MutableOid4vpVerifierInstanceIdProvider {
        override fun currentInstanceId(): String? = id
        override fun setCurrentInstanceId(instanceId: String) { id = instanceId }
        override fun clearCurrentInstanceId() { id = null }
    }

    @Test
    fun responseTypeValidationMatchesTheImplementedVerifierCapability() {
        assertNull(validateCreateAuthResponseType(null))
        assertNull(validateCreateAuthResponseType(""))
        assertNull(validateCreateAuthResponseType("VP_TOKEN"))
        assertEquals("ILLEGAL_ARGUMENT_ERROR", validateCreateAuthResponseType("id_token")?.code)
        assertEquals("ILLEGAL_ARGUMENT_ERROR", validateCreateAuthResponseType("vp_token id_token")?.code)
    }

    @Test
    fun correlationAndStateMustIdentifyTheSameSession() {
        assertEquals("business-1", assertIs<Ok<String>>(resolveSessionCorrelationId("business-1", null) { "generated" }).value)
        assertEquals("state-1", assertIs<Ok<String>>(resolveSessionCorrelationId(null, "state-1") { "generated" }).value)
        assertEquals("same", assertIs<Ok<String>>(resolveSessionCorrelationId("same", "same") { "generated" }).value)
        assertEquals("generated", assertIs<Ok<String>>(resolveSessionCorrelationId(null, null) { "generated" }).value)

        val mismatch = resolveSessionCorrelationId("business-1", "state-1") { "generated" }
        assertEquals("ILLEGAL_ARGUMENT_ERROR", assertIs<Err<IdkError>>(mismatch).error.code)
    }

    @Test
    fun responseBehaviorRewriteChangesOnlyCallbackAndRedirect() {
        val original = session()
        val callback =
            AuthorizationSessionCallbackConfig(
                url = "https://example.com/callback",
                statuses = listOf(AuthorizationSessionStatus.AUTHORIZATION_RESPONSE_VERIFIED),
            )

        val updated =
            original.withUniversalResponseBehavior(
                callback = callback,
                directPostResponseRedirectUri = "https://example.com/done",
            )

        assertEquals(
            original.copy(
                callback = callback,
                directPostResponseRedirectUri = "https://example.com/done",
            ),
            updated,
        )
        assertEquals(original.expiresAt, updated.expiresAt)
    }

    private fun session(): AuthorizationSession =
        AuthorizationSession(
            instanceId = "verifier-instance-universal-create-test",
            sessionId = "session-1",
            correlationId = "correlation-1",
            dcqlQuery =
                DcqlQuery(
                    credentials =
                        listOf(
                            DcqlCredentialQuery(
                                id = "credential",
                                format = "dc+sd-jwt",
                                meta = sdJwtVcMeta("urn:test:credential"),
                            ),
                        ),
                ),
            authorizationRequest =
                AuthorizationRequest(
                    clientId = "https://verifier.example.com",
                    redirectUri = "https://verifier.example.com/response",
                    state = "correlation-1",
                ),
            status = AuthorizationSessionStatus.AUTHORIZATION_REQUEST_CREATED,
            createdAt = 1_000L,
            updatedAt = 1_000L,
            expiresAt = 43_000L,
        )
}
