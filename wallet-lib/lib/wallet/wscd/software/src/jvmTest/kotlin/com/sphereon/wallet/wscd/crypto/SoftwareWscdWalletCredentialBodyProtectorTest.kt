/*
 * Copyright 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

package com.sphereon.wallet.wscd.crypto

import com.sphereon.core.api.session.asCoreApiServiceGraph
import com.sphereon.core.compat.Uuid
import com.sphereon.crypto.core.kms.asKeyManagerServiceGraph
import com.sphereon.crypto.kms.provider.software.SoftwareKmsProviderFactoryImpl
import com.sphereon.wallet.credential.store.WalletCredentialProtectedDocumentRole
import com.sphereon.wallet.wscd.testfixtures.createWalletAppGraph
import com.sphereon.wallet.wscd.software.SoftwareKmsProviderRegistrar
import com.sphereon.wallet.wscd.SoftwareWscdKeyStoreConfiguration
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Unit tests for [SoftwareWscdWalletCredentialBodyProtector], which lives in this module.
 */
class SoftwareWscdWalletCredentialBodyProtectorTest {
    @Test
    fun protectOpenRoundTripUsesRealKmsAndBindsAadToWalletRecordAndInstance() =
        runTest {
            val protector = createProtector()
            val plaintext = "credential-body-secret".encodeToByteArray()

            val protectedBody = protector.protect("wallet-a", "record-1", "instance-1", plaintext)

            assertTrue(protectedBody.isOk)
            assertFalse(protectedBody.value.decodeToString().contains("credential-body-secret"))
            val opened = protector.open("wallet-a", "record-1", "instance-1", protectedBody.value)
            assertTrue(opened.isOk)
            assertEquals("credential-body-secret", opened.value.decodeToString())
            assertTrue(protector.open("wallet-b", "record-1", "instance-1", protectedBody.value).isErr)
            assertTrue(protector.open("wallet-a", "record-2", "instance-1", protectedBody.value).isErr)
            assertTrue(protector.open("wallet-a", "record-1", "instance-2", protectedBody.value).isErr)
        }

    @Test
    fun refreshTokenRoleUsesDistinctAuthenticatedData() =
        runTest {
            val protector = createProtector()
            val plaintext = "refresh-token-secret".encodeToByteArray()
            val protectedToken =
                protector.protect(
                    "wallet-a",
                    "record-refresh-a",
                    "refresh-token",
                    plaintext,
                    WalletCredentialProtectedDocumentRole.REFRESH_TOKEN,
                )

            assertTrue(protectedToken.isOk)
            assertFalse(protectedToken.value.decodeToString().contains("refresh-token-secret"))
            val opened =
                protector.open(
                    "wallet-a",
                    "record-refresh-a",
                    "refresh-token",
                    protectedToken.value,
                    WalletCredentialProtectedDocumentRole.REFRESH_TOKEN,
                )
            assertTrue(opened.isOk)
            assertEquals("refresh-token-secret", opened.value.decodeToString())
            assertTrue(
                protector.open("wallet-a", "record-refresh-a", "refresh-token", protectedToken.value).isErr,
            )
        }

    @Test
    fun openRejectsFormerKmsProtectedBodyEnvelope() =
        runTest {
            val protector = createProtector()
            val unsupportedEnvelope =
                """
                {
                  "version": 1,
                  "protection": "kms-a256gcm",
                  "algorithm": "A256GCM",
                  "keyAlias": "wallet-units/wallet-a/credential-body/a256gcm",
                  "iv": "",
                  "authTag": "",
                  "ciphertext": ""
                }
                """.trimIndent().encodeToByteArray()

            val result = protector.open("wallet-a", "record-1", "instance-1", unsupportedEnvelope)

            assertTrue(result.isErr)
            assertEquals("UNSUPPORTED_OPERATION", result.error.code)
        }

    private fun createProtector(): SoftwareWscdWalletCredentialBodyProtector {
        val sessionId = "wallet-body-protector-${Uuid.v4String()}"
        val app =
            createWalletAppGraph(
                application = "WalletBodyProtectorTest",
                appId = "com.sphereon.wallet.body-protector-test",
                profile = "test",
                version = "0.1.0",
            )
        val userContext = app.userContextManager.getAnonymous()
        val session = userContext.sessionContextManager.createOrGetFromId(sessionId, principalType = com.sphereon.di.context.PrincipalType.USER)
        val kms = session.graph.asKeyManagerServiceGraph().keyManagerService
        val softwareKmsProviderFactory = (app as SoftwareKmsProviderFactoryImpl.Graph).softwareKmsProvider
        val registrar =
            SoftwareKmsProviderRegistrar(
                keyManagerService = kms,
                softwareKmsProviderFactory = softwareKmsProviderFactory,
                execution = session.asCoreApiServiceGraph().serviceExecution,
                app = app,
                keyStoreConfiguration = SoftwareWscdKeyStoreConfiguration.InMemoryForTestingOnly,
                sessionId = sessionId,
            )
        return SoftwareWscdWalletCredentialBodyProtector(kms, registrar)
    }
}
