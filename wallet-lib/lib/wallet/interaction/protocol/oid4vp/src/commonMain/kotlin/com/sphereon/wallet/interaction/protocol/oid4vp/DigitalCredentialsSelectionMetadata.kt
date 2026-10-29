/*
 * Copyright 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

package com.sphereon.wallet.interaction.protocol.oid4vp

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray

/** Platform-selected Digital Credentials API identifiers forwarded as holder metadata. */
internal data class DigitalCredentialsSelectionMetadata(
    val selectedEntryId: String?,
    val selectedCredentialSetId: String?,
    val selectedCredentialIds: List<String>,
    val hasSelectedSet: Boolean,
) {
    /** The selected set, or selected entry when the platform returned no set, is an exact allow-list. */
    val constrainsCredentialIds: Boolean get() = hasSelectedSet || selectedEntryId != null
    val requiredCredentialIds: List<String>
        get() = if (hasSelectedSet) selectedCredentialIds else selectedEntryId?.let(::listOf).orEmpty()

    fun restrictCandidates(candidates: Map<String, List<String>>): RestrictedCredentialCandidates {
        if (!constrainsCredentialIds) return RestrictedCredentialCandidates(candidates, emptyList())
        val requiredIds = requiredCredentialIds
        val selected = requiredIds.toSet()
        val unavailable = requiredIds.filterNot { id -> candidates.values.any { id in it } }
        return RestrictedCredentialCandidates(
            byRequirement = candidates.mapValues { (_, ids) -> ids.filter(selected::contains) },
            unavailableSelectedIds = unavailable,
        )
    }

    companion object {
        const val SELECTED_ENTRY_ID_KEY = "digital_credentials.selected_entry_id"
        const val SELECTED_CREDENTIAL_SET_ID_KEY = "digital_credentials.selected_credential_set_id"
        const val SELECTED_CREDENTIAL_IDS_KEY = "digital_credentials.selected_credential_ids"

        fun parse(attributes: Map<String, String>): DigitalCredentialsSelectionMetadata? {
            val hasEntry = SELECTED_ENTRY_ID_KEY in attributes
            val hasSet = SELECTED_CREDENTIAL_SET_ID_KEY in attributes
            val hasIds = SELECTED_CREDENTIAL_IDS_KEY in attributes
            if (!hasEntry && !hasSet && !hasIds) return null

            val entryId = attributes[SELECTED_ENTRY_ID_KEY]
            val setId = attributes[SELECTED_CREDENTIAL_SET_ID_KEY]
            require(entryId == null || entryId.isNotBlank()) { "digital_credentials_selected_entry_id_invalid" }
            require(setId == null || setId.isNotBlank()) { "digital_credentials_selected_credential_set_id_invalid" }
            require(!hasIds || setId != null) { "digital_credentials_selected_credential_set_missing" }

            val ids =
                if (!hasIds) {
                    emptyList()
                } else {
                    val value = Json.parseToJsonElement(requireNotNull(attributes[SELECTED_CREDENTIAL_IDS_KEY]))
                    val strings = value.jsonArray.map { element ->
                        val id = (element as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull
                            ?: error("digital_credentials_selected_credential_ids_invalid")
                        require(id.isNotBlank()) { "digital_credentials_selected_credential_ids_invalid" }
                        id
                    }
                    require(strings.distinct().size == strings.size) { "digital_credentials_selected_credential_ids_duplicate" }
                    strings
                }
            require(setId == null || entryId == null || entryId in ids) {
                "digital_credentials_selected_entry_not_in_selected_set"
            }

            return DigitalCredentialsSelectionMetadata(
                selectedEntryId = entryId,
                selectedCredentialSetId = setId,
                selectedCredentialIds = ids,
                hasSelectedSet = hasSet,
            )
        }
    }
}

internal data class RestrictedCredentialCandidates(
    val byRequirement: Map<String, List<String>>,
    val unavailableSelectedIds: List<String>,
)
