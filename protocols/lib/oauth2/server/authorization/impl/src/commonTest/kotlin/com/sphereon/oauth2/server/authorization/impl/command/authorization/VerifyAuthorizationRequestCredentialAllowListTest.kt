/*
 * Copyright 2023-2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

package com.sphereon.oauth2.server.authorization.impl.command.authorization

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.oauth2.common.config.OAuth2ServersConfig
import com.sphereon.oauth2.common.model.ClientAuthenticationMethod
import com.sphereon.oauth2.common.model.GrantType
import com.sphereon.oauth2.common.model.ResponseType
import com.sphereon.oauth2.server.authorization.command.AuthorizationRequestData
import com.sphereon.oauth2.server.authorization.error.AuthorizationServerError
import com.sphereon.oauth2.server.authorization.impl.testutil.OAuth2ServerTestContext
import com.sphereon.oauth2.server.authorization.impl.testutil.TestOAuth2ServersConfigProvider
import com.sphereon.oauth2.server.authorization.model.ClientRegistration
import com.sphereon.oauth2.server.authorization.model.ClientType
import com.sphereon.oauth2.server.authorization.storage.ClientRegistry
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * RFC 9396 §6 + §10 per-client `authorization_details.credential_configuration_id` allow-list
 * enforcement (Sprint 2 S2-3). Covers:
 *  - null allow-list grandfathers every request (pre-S2-3 behaviour)
 *  - empty allow-list rejects any `credential_configuration_id`
 *  - populated allow-list accepts in-set, rejects out-of-set
 *  - malformed authorization_details JSON is surfaced as `invalid_authorization_details`
 *  - absent authorization_details parameter bypasses the check even with a populated allow-list
 */
class VerifyAuthorizationRequestCredentialAllowListTest {
    private val ctx = OAuth2ServerTestContext("verify-auth-allowlist-test", this)

    private fun createCommand(allowList: Set<String>? = null): VerifyAuthorizationRequestCommandImpl {
        val client =
            ClientRegistration(
                clientId = CLIENT_ID,
                clientName = "Test Client",
                clientType = ClientType.CONFIDENTIAL,
                grantTypes = listOf(GrantType.AUTHORIZATION_CODE),
                responseTypes = listOf(ResponseType.CODE),
                redirectUris = listOf("https://client.example.com/cb"),
                tokenEndpointAuthMethod = ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                credentialConfigurationIds = allowList,
            )
        return VerifyAuthorizationRequestCommandImpl(
            ctx.execution,
            StubClientRegistry(client),
            TestOAuth2ServersConfigProvider(OAuth2ServersConfig()),
            emptySet(),
            com.sphereon.oauth2.server.authorization.impl.provider.NoCredentialIssuerAudienceResolver(),
            Oid4vciUnregisteredWalletAdmissionRule(),
            com.sphereon.oauth2.server.authorization.impl.testutil.fixedAsInstanceIdProvider(),
        )
    }

    private fun requestWithAuthorizationDetails(ad: String?): AuthorizationRequestData =
        AuthorizationRequestData(
            clientId = CLIENT_ID,
            redirectUri = "https://client.example.com/cb",
            responseType = listOf(ResponseType.CODE),
            scope = null,
            state = "xyz",
            codeChallenge = "a".repeat(43),
            codeChallengeMethod = com.sphereon.oauth2.common.model.PkceMethod.S256,
            additionalParameters = if (ad == null) emptyMap() else mapOf("authorization_details" to ad),
        )

    @Test
    fun nullAllowListGrandfathersRequest() =
        runTest {
            val cmd = createCommand(allowList = null)
            val ad = """[{"type":"openid_credential","credential_configuration_id":"PassportCredential"}]"""
            val result = cmd.execute(requestWithAuthorizationDetails(ad))
            assertTrue(result.isOk, "null allow-list should grandfather: $result")
        }

    @Test
    fun emptyAllowListRejectsAny() =
        runTest {
            val cmd = createCommand(allowList = emptySet())
            val ad = """[{"type":"openid_credential","credential_configuration_id":"EmployeeID"}]"""
            val result = cmd.execute(requestWithAuthorizationDetails(ad))
            assertTrue(result.isErr, "empty allow-list should reject any credential_configuration_id")
            val code = extractCode(result)
            assertEquals("invalid_authorization_details", code)
        }

    @Test
    fun populatedAllowListAcceptsInSet() =
        runTest {
            val cmd = createCommand(allowList = setOf("EmployeeID", "ContractorID"))
            val ad = """[{"type":"openid_credential","credential_configuration_id":"EmployeeID"}]"""
            val result = cmd.execute(requestWithAuthorizationDetails(ad))
            assertTrue(result.isOk, "in-set credential_configuration_id should pass: $result")
        }

    @Test
    fun populatedAllowListRejectsOutOfSet() =
        runTest {
            val cmd = createCommand(allowList = setOf("EmployeeID"))
            val ad = """[{"type":"openid_credential","credential_configuration_id":"PassportCredential"}]"""
            val result = cmd.execute(requestWithAuthorizationDetails(ad))
            assertTrue(result.isErr, "out-of-set credential_configuration_id should reject")
            assertEquals("invalid_authorization_details", extractCode(result))
        }

    @Test
    fun malformedAuthorizationDetailsRejected() =
        runTest {
            val cmd = createCommand(allowList = setOf("EmployeeID"))
            val result = cmd.execute(requestWithAuthorizationDetails("not-json"))
            assertTrue(result.isErr, "malformed JSON should reject")
            assertEquals("invalid_authorization_details", extractCode(result))
        }

    @Test
    fun absentAuthorizationDetailsBypassesCheck() =
        runTest {
            val cmd = createCommand(allowList = setOf("EmployeeID"))
            val result = cmd.execute(requestWithAuthorizationDetails(null))
            assertTrue(result.isOk, "absent authorization_details should bypass: $result")
        }

    private fun extractCode(result: IdkResult<*, *>): String? = (result.error as? com.sphereon.core.api.error.IdkError)?.code

    companion object {
        private const val CLIENT_ID = "test-client"
    }

    private class StubClientRegistry(
        private val client: ClientRegistration,
    ) : ClientRegistry {
        override suspend fun getClient(clientId: String): IdkResult<ClientRegistration?, AuthorizationServerError.StorageError> = Ok(if (clientId == client.clientId) client else null)

        override suspend fun registerClient(registration: ClientRegistration): IdkResult<ClientRegistration, AuthorizationServerError.StorageError> = Ok(registration)

        override suspend fun updateClient(
            clientId: String,
            registration: ClientRegistration,
        ): IdkResult<ClientRegistration, AuthorizationServerError> = Ok(registration)

        override suspend fun deleteClient(clientId: String): IdkResult<Unit, AuthorizationServerError> = Ok(Unit)

        override suspend fun listClients(
            limit: Int,
            offset: Int,
        ): IdkResult<List<ClientRegistration>, AuthorizationServerError.StorageError> = Ok(emptyList())

        override suspend fun findClientsByName(name: String): IdkResult<List<ClientRegistration>, AuthorizationServerError.StorageError> = Ok(emptyList())

        override suspend fun clientExists(clientId: String): IdkResult<Boolean, AuthorizationServerError.StorageError> = Ok(true)

        override suspend fun verifyClientCredentials(
            clientId: String,
            clientSecret: String,
        ): IdkResult<Boolean, AuthorizationServerError.StorageError> = Ok(true)
    }
}
