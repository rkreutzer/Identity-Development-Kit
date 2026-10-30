/* (c) 2026 Sphereon International B.V. Licensed under the Apache License, Version 2.0 */
@file:OptIn(kotlin.uuid.ExperimentalUuidApi::class)
package com.sphereon.data.store.party.result

import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.uuid.Uuid

class IdentityResultOwnershipTest {
    @Test
    fun legacyResponseWithoutOwnerDecodesAndPersistedOwnerSurvivesSerialization() {
        val json = Json
        val legacy = """{"partyId":"4c7e79f0-9f6d-4a38-8455-6e0b3f4f5a10","tenantId":"tenant-acme","identityRole":"FEDERATION_TRUST_ROOT","isDefault":false,"createdAt":"2026-06-18T09:15:00Z","updatedAt":"2026-06-18T09:15:00Z"}"""
        val decoded = json.decodeFromString(IdentityResult.serializer(), legacy)
        assertNull(decoded.ownerId)
        val owner = Uuid.parse("0c868ec0-0715-48a9-9908-851d78b742c8")
        val owned = decoded.copy(ownerId = owner)
        val roundTrip = json.decodeFromString(IdentityResult.serializer(), json.encodeToString(IdentityResult.serializer(), owned))
        assertEquals(owner, roundTrip.ownerId)
        assertEquals(decoded.toIdentity(), roundTrip.toIdentity(), "Ownership projection must not alter the core identity")
    }
}
