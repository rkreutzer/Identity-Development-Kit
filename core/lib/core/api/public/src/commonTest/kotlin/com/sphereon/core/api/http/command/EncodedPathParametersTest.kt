package com.sphereon.core.api.http.command

import com.sphereon.core.api.http.GenericHttpRequest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class EncodedPathParametersTest {
    private val pattern = "/api/tenants/{tenantId}/subordinates/{entity_id}"
    private val identifier = "https%3A%2F%2Fop.example.org%2Fpath%3Fx%3D1%252F2"

    @Test fun encodedUriIsAllowedOnlyForDeclaredOpaqueParameter() {
        val path = "/api/tenants/acme/subordinates/$identifier"
        assertTrue(hasUnsafeEndpointPath(path, pattern, emptySet()))
        assertFalse(hasUnsafeEndpointPath(path, pattern, setOf("entity_id")))
        assertEquals("https://op.example.org/path?x=1%2F2",
            GenericHttpRequest(method = "GET", path = path).withExtractedParams(pattern).pathParameters["entity_id"])
    }

    @Test fun encodedSelectorStillFailsWhenResourceParameterOptsIn() {
        assertTrue(hasUnsafeEndpointPath("/api/tenants/acme%2Fother/subordinates/$identifier", pattern, setOf("entity_id")))
        assertTrue(hasUnsafeEndpointPath("/api/tenants/acme/../subordinates/$identifier", pattern, setOf("entity_id")))
        assertTrue(hasUnsafeEndpointPath("/api//tenants/acme/subordinates/$identifier", pattern, setOf("entity_id")))
    }

    @Test fun opaqueParameterRejectsMalformedEncodingAndStandaloneDotSegments() {
        for (value in listOf("%", "%2", "%GG", ".", "..", "%2e%2E", "raw\\value")) {
            assertTrue(hasUnsafeEndpointPath("/api/tenants/acme/subordinates/$value", pattern, setOf("entity_id")), value)
        }
    }

    @Test fun encodedUriDoesNotChangeRouteBoundaries() {
        assertFalse(GenericHttpRequest(method = "GET", path = "/api/tenants/acme/subordinates/https://op.example.org")
            .matches("GET", pattern))
        assertTrue(hasUnsafeEndpointPath("/api/tenants/acme/subordinates/https://op.example.org", pattern, setOf("entity_id")))
    }
}
