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

package com.sphereon.openid.oid4vci.rest.validation

import com.sphereon.core.api.error.ErrorCategory
import com.sphereon.openid.oid4vci.rest.CreateCredentialOfferInput
import com.sphereon.openid.oid4vci.rest.error.Oid4vciRestError
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class CreateCredentialOfferInputValidationTest {
    private fun input(
        correlationId: String? = null,
        ttlSeconds: Long? = null,
        issuerInstanceId: String? = null,
    ) = CreateCredentialOfferInput(
        credentialConfigurationIds = listOf("PID"),
        correlationId = correlationId,
        ttlSeconds = ttlSeconds,
        issuerInstanceId = issuerInstanceId,
    )

    private fun messages(input: CreateCredentialOfferInput): List<String> = validateCreateCredentialOfferInput(input).errors.map { it.message }

    @Test
    fun shouldAcceptAnInputWithoutOptionalFields() {
        assertTrue(validateCreateCredentialOfferInput(input()).isValid)
    }

    @Test
    fun shouldTakeAnyCorrelationIdBecauseItIsAReleasedField() {
        for (id in listOf("Az09._~:-", "a/b", "a b", "a?b", "ä", "k".repeat(1000))) {
            assertTrue(validateCreateCredentialOfferInput(input(correlationId = id)).isValid, "'$id' must stay valid")
        }
    }

    @Test
    fun shouldBoundTheOfferLifetimeAtBothEnds() {
        assertTrue(validateCreateCredentialOfferInput(input(ttlSeconds = 1)).isValid)
        assertTrue(validateCreateCredentialOfferInput(input(ttlSeconds = CreateCredentialOfferLimits.TTL_SECONDS_MAX)).isValid)
        assertTrue(messages(input(ttlSeconds = 0)).contains("ttl_seconds must be at least 1"))
        assertTrue(messages(input(ttlSeconds = CreateCredentialOfferLimits.TTL_SECONDS_MAX + 1)).any { it.startsWith("ttl_seconds must not exceed") })
    }

    @Test
    fun shouldRequireACanonicalIssuerInstanceId() {
        assertTrue(validateCreateCredentialOfferInput(input(issuerInstanceId = "00000000-0000-4000-8000-000000000001")).isValid)
        assertTrue(messages(input(issuerInstanceId = "default")).contains("issuer_instance_id must be a canonical UUID"))
        assertTrue(messages(input(issuerInstanceId = "00000000-0000-4000-8000-00000000000A")).contains("issuer_instance_id must be a canonical UUID"), "upper case is not canonical")
    }

    @Test
    fun shouldClassifyAValidationErrorAsAClientError() {
        val error = Oid4vciRestError.ValidationError(errors = emptyList())

        assertEquals(ErrorCategory.VALIDATION, error.category, "an HTTP caller must be answered with a 4xx, not a 500")
        assertEquals("OID4VCI_REST_VALIDATION_ERROR", error.code)
    }
}
