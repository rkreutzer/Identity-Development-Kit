package com.sphereon.oauth2.server.authorization.impl.http.describe

import com.sphereon.core.api.http.config.UniversalHttpConfig
import com.sphereon.core.api.http.describe.EndpointAuthPolicy
import com.sphereon.core.api.http.dispatch.DefaultEndpointAuthCatalog
import com.sphereon.oauth2.server.authorization.command.login.LoginWebAuthnAssertionBeginHttpEndpointCommand
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class LoginAssertionPublicRouteContractTest {
    @Test
    fun assertionBeginDeclaresItsPreauthenticationBoundary() {
        assertEquals(EndpointAuthPolicy.PUBLIC, LoginWebAuthnAssertionBeginHttpEndpointCommand.ENDPOINT.authPolicy)
    }

    @Test
    fun actualCatalogPreservesPublicClassificationUnderHostedAsMount() {
        val catalog = DefaultEndpointAuthCatalog(setOf(OAuth2LoginHttpAdapterDescriptorProvider()), UniversalHttpConfig.DEFAULT)
        for (path in listOf("/login/webauthn/assertion/begin", "/as/connector-smoke/login/webauthn/assertion/begin")) {
            assertTrue(catalog.isPublic("POST", path), path)
            for (method in listOf("GET", "PUT", "DELETE")) assertFalse(catalog.isPublic(method, path), "$method $path")
        }
        for (path in listOf("/as/connector-smoke/login/webauthn/assertion/begin/extra", "/api/kms/v1/keys", "/api/authorization-server/v1/identities")) {
            assertFalse(catalog.isPublic("POST", path), path)
        }
    }
}
