package com.sphereon.oauth2.server.authorization.impl.command.authorization

import com.sphereon.oauth2.common.model.PkceMethod
import com.sphereon.oauth2.common.model.ResponseType
import com.sphereon.oauth2.common.model.GrantType
import com.sphereon.oauth2.common.config.OAuth2ServerInstanceConfig
import com.sphereon.oauth2.common.config.OAuth2ServersConfig
import com.sphereon.oauth2.server.authorization.command.AuthorizationRequestData
import com.sphereon.oauth2.server.authorization.command.VerifyPushedAuthorizationRequestArgs
import com.sphereon.oauth2.server.authorization.impl.command.par.VerifyPushedAuthorizationRequestCommandImpl
import com.sphereon.oauth2.server.authorization.impl.testutil.OAuth2ServerTestContext
import com.sphereon.oauth2.server.authorization.impl.testutil.StubClientRegistry
import com.sphereon.oauth2.server.authorization.impl.testutil.TestOAuth2ServersConfigProvider
import com.sphereon.oauth2.server.authorization.provider.CredentialIssuerAudience
import com.sphereon.oauth2.server.authorization.provider.CredentialIssuerAudienceResolver
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class Oid4vciUnregisteredWalletAdmissionRuleTest {
    private val context = OAuth2ServerTestContext("oid4vci-wallet-admission", this)
    private val rule = Oid4vciUnregisteredWalletAdmissionRule()
    private val issuer = CredentialIssuerAudience("https://issuer.example", setOf("credential_scope"))

    @Test
    fun noBoundIssuerRefusesAdmission() = runTest {
        assertNull(rule.admit(validRequest(), emptyList()))
    }

    @Test
    fun generalScopeIsRefused() = runTest {
        assertNull(rule.admit(validRequest().copy(scope = "openid"), listOf(issuer)))
    }

    @Test
    fun requestWithoutParIsRefused() = runTest {
        assertNull(rule.admit(validRequest().copy(requestUri = null), listOf(issuer)))
    }

    @Test
    fun requestWithoutS256IsRefused() = runTest {
        assertNull(rule.admit(validRequest().copy(codeChallengeMethod = PkceMethod.PLAIN), listOf(issuer)))
    }

    @Test
    fun oid4vciRequestIsCodeOnlyAndAudienceBound() = runTest {
        val admission = rule.admit(validRequest(), listOf(issuer))
        assertEquals(setOf("https://issuer.example"), admission?.audiences)
        assertTrue(GrantType.AUTHORIZATION_CODE in admission!!.client.grantTypes)
        assertEquals(true, admission?.client?.requirePushedAuthorizationRequests)
    }

    @Test
    fun pushedOid4vciRequestCanBeAdmittedBeforeItHasARequestUri() = runTest {
        val admission = rule.admit(validRequest().copy(requestUri = null), listOf(issuer), isPushedAuthorizationRequest = true)
        assertEquals(setOf("https://issuer.example"), admission?.audiences)
    }

    @Test
    fun authorizationEndpointAdmitsBoundUnregisteredWallet() = runTest {
        val command = VerifyAuthorizationRequestCommandImpl(
            context.execution,
            StubClientRegistry(),
            configProvider(),
            emptySet(),
            resolver(),
            rule,
            com.sphereon.oauth2.server.authorization.impl.testutil.fixedAsInstanceIdProvider(),
        )
        val result = command.execute(validRequest())
        assertTrue(result.isOk)
        assertEquals(listOf("https://issuer.example"), result.value.admittedAudiences)
    }

    @Test
    fun parEndpointAdmitsBoundUnregisteredWalletBeforeRequestUriExists() = runTest {
        val command = VerifyPushedAuthorizationRequestCommandImpl(
            context.execution,
            StubClientRegistry(),
            configProvider(),
            resolver(),
            rule,
        )
        val result = command.execute(VerifyPushedAuthorizationRequestArgs(validRequest().copy(requestUri = null), "wallet-client"))
        assertTrue(result.isOk)
        assertEquals(listOf("https://issuer.example"), result.value.admittedAudiences)
    }

    private fun resolver() = object : CredentialIssuerAudienceResolver {
        override suspend fun boundCredentialIssuers(): List<CredentialIssuerAudience> = listOf(issuer)
    }

    private fun configProvider() = TestOAuth2ServersConfigProvider(
        OAuth2ServersConfig(
            servers = mapOf("default" to OAuth2ServerInstanceConfig(issuer = "https://as.example", responseTypesSupported = setOf("code"))),
            defaultServer = "default",
        ),
    )

    private fun validRequest() =
        AuthorizationRequestData(
            clientId = "wallet-client",
            redirectUri = "wallet:/callback",
            responseType = listOf(ResponseType.CODE),
            scope = "credential_scope",
            codeChallenge = "a".repeat(43),
            codeChallengeMethod = PkceMethod.S256,
            requestUri = "urn:ietf:params:oauth:request_uri:opaque",
        )
}
