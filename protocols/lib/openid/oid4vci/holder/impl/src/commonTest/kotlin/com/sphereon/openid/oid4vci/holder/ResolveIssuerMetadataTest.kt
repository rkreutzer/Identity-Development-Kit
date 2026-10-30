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

package com.sphereon.openid.oid4vci.holder

import com.sphereon.openid.oid4vci.common.Oid4vciUrls
import com.sphereon.openid.oid4vci.common.model.CredentialIssuerMetadata
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

/**
 * Unit tests for ResolveIssuerMetadataCommandImpl.
 *
 * Covers:
 * - Well-known URL construction (OID4VCI 1.0 Final Section 12.2.2)
 * - Metadata deserialization from spec example JSON
 *
 * No HTTP calls are made — these tests use the internal URL-building
 * and JSON-parsing logic directly.
 */
class ResolveIssuerMetadataTest {
    // ── Well-known URL construction tests ──────────────────────────────────────

    @Test
    fun rootIssuerUrlProducesWellKnownUrl() {
        val result = Oid4vciUrls.buildWellKnownUrl("https://issuer.example.com")
        assertEquals("https://issuer.example.com/.well-known/openid-credential-issuer", result)
    }

    @Test
    fun issuerUrlWithPathInsertsWellKnownBetweenHostAndPath() {
        val result = Oid4vciUrls.buildWellKnownUrl("https://issuer.example.com/tenant1")
        assertEquals("https://issuer.example.com/.well-known/openid-credential-issuer/tenant1", result)
    }

    @Test
    fun issuerUrlWithDeepPathInsertsWellKnownBetweenHostAndPath() {
        val result = Oid4vciUrls.buildWellKnownUrl("https://issuer.example.com/org/tenant1")
        assertEquals("https://issuer.example.com/.well-known/openid-credential-issuer/org/tenant1", result)
    }

    @Test
    fun issuerUrlWithPortProducesWellKnownUrl() {
        val result = Oid4vciUrls.buildWellKnownUrl("https://issuer.example.com:8443")
        assertEquals("https://issuer.example.com:8443/.well-known/openid-credential-issuer", result)
    }

    @Test
    fun issuerUrlWithPortAndPathInsertsWellKnownBetweenHostAndPath() {
        val result = Oid4vciUrls.buildWellKnownUrl("https://issuer.example.com:8443/tenant1")
        assertEquals("https://issuer.example.com:8443/.well-known/openid-credential-issuer/tenant1", result)
    }

    @Test
    fun issuerUrlWithTerminatingPathSlashPreservesPath() {
        val result = Oid4vciUrls.buildWellKnownUrl("https://issuer.example.com:8443/test/a/issuer/")
        assertEquals("https://issuer.example.com:8443/.well-known/openid-credential-issuer/test/a/issuer/", result)
    }

    @Test
    fun terminatingPathSlashRoundTripsWithoutChangingIssuerIdentity() {
        val issuer = "https://issuer.example.com:8443/test/a/issuer/"
        val metadata = "https://issuer.example.com:8443/.well-known/openid-credential-issuer/test/a/issuer/"
        assertEquals(issuer, Oid4vciUrls.buildIssuerUrl(issuer))
        assertEquals(issuer, Oid4vciUrls.buildIssuerUrl(metadata))
        assertEquals(metadata, Oid4vciUrls.buildWellKnownUrl(metadata))
        assertEquals(metadata, Oid4vciUrls.buildWellKnownUrl(Oid4vciUrls.buildIssuerUrl(metadata)))
    }

    @Test
    fun rootPathSlashIsPreservedAsPartOfIssuerIdentifier() {
        val issuer = "https://issuer.example.com/"
        val metadata = "https://issuer.example.com/.well-known/openid-credential-issuer/"
        assertEquals(metadata, Oid4vciUrls.buildWellKnownUrl(issuer))
        assertEquals(issuer, Oid4vciUrls.buildIssuerUrl(metadata))
    }

    @Test
    fun fullWellKnownUrlIsUsedAsMetadataUrl() {
        val metadataUrl = "https://issuer.example.com/.well-known/openid-credential-issuer/tenant1"
        val result = Oid4vciUrls.buildWellKnownUrl(metadataUrl)
        assertEquals(metadataUrl, result)
    }

    @Test
    fun issuerUrlCanBeDerivedFromFullWellKnownUrl() {
        val result = Oid4vciUrls.buildIssuerUrl("https://issuer.example.com/.well-known/openid-credential-issuer/org/tenant1")
        assertEquals("https://issuer.example.com/org/tenant1", result)
    }

    @Test
    fun franceIdentiteWellKnownUrlRoundTripsToIssuerAndBack() {
        val wellKnownUrl = "https://api.playground.france-identite.gouv.fr/.well-known/openid-credential-issuer/igrantio/issuer-backend"
        val issuerUrl = "https://api.playground.france-identite.gouv.fr/igrantio/issuer-backend"

        assertEquals(wellKnownUrl, Oid4vciUrls.buildWellKnownUrl(wellKnownUrl))
        assertEquals(wellKnownUrl, Oid4vciUrls.buildWellKnownUrl(issuerUrl))
        assertEquals(issuerUrl, Oid4vciUrls.buildIssuerUrl(wellKnownUrl))
    }

    // ── Metadata deserialization tests ─────────────────────────────────────────

    /**
     * Spec example from OID4VCI 1.0 Appendix B.
     */
    @Test
    fun deserializeSpecExampleMetadata() {
        val specJson =
            """
            {
              "credential_issuer": "https://credential-issuer.example.com",
              "authorization_servers": ["https://keycloak.example.com/realms/test"],
              "credential_endpoint": "https://credential-issuer.example.com/credential",
              "nonce_endpoint": "https://credential-issuer.example.com/nonce",
              "deferred_credential_endpoint": "https://credential-issuer.example.com/credential/deferred",
              "notification_endpoint": "https://credential-issuer.example.com/notification",
              "credential_configurations_supported": {
                "UniversityDegreeCredential": {
                  "format": "jwt_vc_json",
                  "scope": "UniversityDegree",
                  "cryptographic_binding_methods_supported": ["did:example"],
                  "credential_signing_alg_values_supported": ["ES256"],
                  "display": [
                    {
                      "name": "University Credential",
                      "locale": "en-US"
                    }
                  ]
                }
              }
            }
            """.trimIndent()

        val json = Json { ignoreUnknownKeys = true }
        val metadata = json.decodeFromString(CredentialIssuerMetadata.serializer(), specJson)

        assertEquals("https://credential-issuer.example.com", metadata.credentialIssuer)
        assertEquals("https://credential-issuer.example.com/credential", metadata.credentialEndpoint)
        assertNotNull(metadata.nonceEndpoint)
        assertNotNull(metadata.deferredCredentialEndpoint)
        assertNotNull(metadata.notificationEndpoint)
        assertEquals(listOf("https://keycloak.example.com/realms/test"), metadata.authorizationServers)
        assertEquals(1, metadata.credentialConfigurationsSupported.size)
        val config = metadata.credentialConfigurationsSupported["UniversityDegreeCredential"]
        assertNotNull(config)
        assertEquals("jwt_vc_json", config.format)
    }
}
