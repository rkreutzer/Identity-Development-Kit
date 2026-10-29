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

package com.sphereon.openid.oid4vci.rest

import com.sphereon.core.api.http.GenericHttpRequest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class Oid4vciRestPathsTest {
    private val instanceId = "3f9c2b64-6d2e-4a57-9c1a-0b7e5d8a1f42"

    @Test
    fun shouldListTheInstanceScopedRouteFirstAndKeepTheRouteWithoutAnInstance() {
        assertEquals(
            listOf("/instances/{instanceId}/backend/credential/offers", "/backend/credential/offers"),
            CreateCredentialOfferEndpointCommand.ENDPOINT.pathPatterns,
        )
        assertEquals(
            listOf("/instances/{instanceId}/backend/credential/offers/{correlation_id}", "/backend/credential/offers/{correlation_id}"),
            GetCredentialOfferStatusEndpointCommand.ENDPOINT.pathPatterns,
        )
        assertEquals(
            GetCredentialOfferStatusEndpointCommand.ENDPOINT.pathPatterns,
            DeleteCredentialOfferEndpointCommand.ENDPOINT.pathPatterns,
        )
    }

    @Test
    fun shouldExtractTheInstanceAndTheCorrelationIdFromTheInstanceScopedRoute() {
        val request =
            GenericHttpRequest(method = "GET", path = "/instances/$instanceId/backend/credential/offers/order-1")
                .withRouteParams(GetCredentialOfferStatusEndpointCommand.ENDPOINT)

        assertEquals(instanceId, request.pathParams[Oid4vciRestPaths.INSTANCE_ID_PARAM])
        assertEquals("order-1", request.pathParams[Oid4vciRestPaths.CORRELATION_ID_PARAM])
    }

    @Test
    fun shouldExtractOnlyTheCorrelationIdFromTheRouteWithoutAnInstance() {
        val request =
            GenericHttpRequest(method = "GET", path = "/backend/credential/offers/order-1")
                .withRouteParams(GetCredentialOfferStatusEndpointCommand.ENDPOINT)

        assertNull(request.pathParams[Oid4vciRestPaths.INSTANCE_ID_PARAM])
        assertEquals("order-1", request.pathParams[Oid4vciRestPaths.CORRELATION_ID_PARAM])
    }
}
