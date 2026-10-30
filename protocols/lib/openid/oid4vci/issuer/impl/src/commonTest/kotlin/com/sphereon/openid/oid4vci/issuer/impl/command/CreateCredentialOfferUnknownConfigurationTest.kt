/*
 * Copyright 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

package com.sphereon.openid.oid4vci.issuer.impl.command

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.error.IdkError
import com.sphereon.openid.oid4vci.common.model.CredentialOffer
import com.sphereon.openid.oid4vci.issuer.command.CreateCredentialOfferArgs
import com.sphereon.openid.oid4vci.issuer.command.nothingWritten
import com.sphereon.openid.oid4vci.issuer.impl.lifecycle.OfferLifecycleInitializer
import com.sphereon.openid.oid4vci.issuer.impl.testAuthorizationSnapshot
import com.sphereon.openid.oid4vci.issuer.store.CredentialOfferStore
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class CreateCredentialOfferUnknownConfigurationTest {
    private val instanceId = "00000000-0000-4000-8000-000000000021"

    @Test
    fun offerForUnpublishedConfigurationIsRejectedBeforeAnyWrite() =
        runTest {
            val fixture = Fixture()

            val result = fixture.command.execute(args(listOf("EuPid", "DoesNotExist")))

            assertTrue(result.isErr, "An offer for an unpublished configuration must be rejected")
            assertEquals("ILLEGAL_ARGUMENT_ERROR", result.error.code)
            assertTrue(result.error.nothingWritten, "a refusal before any write carries the marker callers read instead of the generic code")
            assertTrue(result.error.message.defaultMessage.contains("DoesNotExist"), result.error.message.defaultMessage)
            assertTrue(fixture.sessionStore.created.isEmpty())
            assertNull(fixture.asBridge.lastRegisterPreAuthCodeArgs)
            assertEquals(0, fixture.offerWrites)
        }

    @Test
    fun offerForPublishedConfigurationIsCreated() =
        runTest {
            val fixture = Fixture()

            val result = fixture.command.execute(args(listOf("EuPid")))

            assertTrue(result.isOk, "error=${if (result.isErr) result.error else null}")
            assertEquals(1, fixture.offerWrites)
        }

    private fun args(configurationIds: List<String>) =
        CreateCredentialOfferArgs(
            instanceId = instanceId,
            issuerId = "https://issuer.example.com/oid4vci",
            credentialConfigurationIds = configurationIds,
            preAuthorizedCodeGrant = true,
            authorizationPolicySnapshot = testAuthorizationSnapshot(instanceId),
        )

    private class Fixture {
        val sessionStore = RecordingSessionStore()
        val asBridge = NoOpAsBridge()
        var offerWrites = 0
        private val offerStore =
            object : CredentialOfferStore by NoOpOfferStore() {
                override suspend fun store(
                    offerId: String,
                    offer: CredentialOffer,
                    ttlSeconds: Long,
                    sessionId: String?,
                ): IdkResult<Unit, IdkError> {
                    offerWrites++
                    return Ok(Unit)
                }
            }
        val command =
            CreateCredentialOfferCommandImpl(
                execution = TestSessionExecution(),
                asBridge = asBridge,
                offerStore = offerStore,
                sessionStore = sessionStore,
                issuerConfigProvider = PublishedConfigurationsIssuerConfigProvider("EuPid"),
                lifecycleInitializer = OfferLifecycleInitializer(),
            )
    }
}
