/*
 * Copyright 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

package com.sphereon.wallet.interaction.protocol.oid4vp

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DigitalCredentialsSelectionMetadataTest {
    @Test
    fun preservesOpaquePlatformIdentifiersAndRestrictsToTheChosenSet() {
        val ids = listOf("record,one", "credential:二")
        val selection =
            DigitalCredentialsSelectionMetadata.parse(
                mapOf(
                    DigitalCredentialsSelectionMetadata.SELECTED_ENTRY_ID_KEY to "credential:二",
                    DigitalCredentialsSelectionMetadata.SELECTED_CREDENTIAL_SET_ID_KEY to "set:opaque/2",
                    DigitalCredentialsSelectionMetadata.SELECTED_CREDENTIAL_IDS_KEY to
                        JsonArray(ids.map { JsonPrimitive(it) }).toString(),
                ),
            )

        assertEquals("credential:二", selection?.selectedEntryId)
        assertEquals("set:opaque/2", selection?.selectedCredentialSetId)
        assertEquals(ids, selection?.selectedCredentialIds)
        assertTrue(selection?.constrainsCredentialIds == true)
    }

    @Test
    fun emptySelectedSetRemainsAnExactEmptyAllowList() {
        val selection =
            DigitalCredentialsSelectionMetadata.parse(
                mapOf(DigitalCredentialsSelectionMetadata.SELECTED_CREDENTIAL_SET_ID_KEY to "selected-empty-set"),
            )

        assertEquals(emptyList(), selection?.selectedCredentialIds)
        assertTrue(selection?.constrainsCredentialIds == true)
        assertEquals(mapOf("pid" to emptyList()), selection?.restrictCandidates(mapOf("pid" to listOf("record-a")))?.byRequirement)
    }

    @Test
    fun rejectsMalformedOrAmbiguousSelectionMetadata() {
        assertFails {
            DigitalCredentialsSelectionMetadata.parse(
                mapOf(DigitalCredentialsSelectionMetadata.SELECTED_CREDENTIAL_IDS_KEY to "[\"credential-a\"]"),
            )
        }
        assertFails {
            DigitalCredentialsSelectionMetadata.parse(
                mapOf(
                    DigitalCredentialsSelectionMetadata.SELECTED_CREDENTIAL_SET_ID_KEY to "set-a",
                    DigitalCredentialsSelectionMetadata.SELECTED_CREDENTIAL_IDS_KEY to "[\"credential-a\",\"credential-a\"]",
                ),
            )
        }
        assertNull(DigitalCredentialsSelectionMetadata.parse(emptyMap()))
    }

    @Test
    fun onlyCredentialsInsideTheSelectedPlatformSetRemainCandidates() {
        val selection =
            DigitalCredentialsSelectionMetadata.parse(
                mapOf(
                    DigitalCredentialsSelectionMetadata.SELECTED_CREDENTIAL_SET_ID_KEY to "set-a",
                    DigitalCredentialsSelectionMetadata.SELECTED_CREDENTIAL_IDS_KEY to "[\"record,b\",\"record-c\"]",
                ),
            )!!

        val restricted = selection.restrictCandidates(mapOf("pid" to listOf("record-a", "record,b"), "address" to listOf("record-c")))

        assertEquals(mapOf("pid" to listOf("record,b"), "address" to listOf("record-c")), restricted.byRequirement)
        assertEquals(emptyList(), restricted.unavailableSelectedIds)
    }

    @Test
    fun selectedEntryWithoutASetRestrictsCandidatesToThatOpaqueEntryId() {
        val selection =
            DigitalCredentialsSelectionMetadata.parse(
                mapOf(DigitalCredentialsSelectionMetadata.SELECTED_ENTRY_ID_KEY to "record:opaque/1"),
            )!!

        val restricted = selection.restrictCandidates(mapOf("pid" to listOf("record-a", "record:opaque/1")))

        assertEquals(mapOf("pid" to listOf("record:opaque/1")), restricted.byRequirement)
        assertEquals(emptyList(), restricted.unavailableSelectedIds)
    }

    @Test
    fun reportsAnyOpaqueCredentialIdThatCannotMatchTheRequest() {
        val selection =
            DigitalCredentialsSelectionMetadata.parse(
                mapOf(
                    DigitalCredentialsSelectionMetadata.SELECTED_CREDENTIAL_SET_ID_KEY to "set-a",
                    DigitalCredentialsSelectionMetadata.SELECTED_CREDENTIAL_IDS_KEY to "[\"record-a\",\"unknown/opaque\"]",
                ),
            )!!

        val restricted = selection.restrictCandidates(mapOf("pid" to listOf("record-a")))

        assertEquals(listOf("unknown/opaque"), restricted.unavailableSelectedIds)
    }
}
