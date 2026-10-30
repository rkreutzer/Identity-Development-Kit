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
 *
 */

@file:OptIn(ExperimentalUuidApi::class)

package com.sphereon.data.store.party.result

import com.sphereon.core.compat.JsExportCompat
import com.sphereon.data.store.party.model.Identity
import com.sphereon.data.store.party.model.IdentityIdentifier
import com.sphereon.data.store.party.model.IdentityPrivacyMode
import com.sphereon.data.store.party.model.IdentityRole
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmOverloads
import kotlin.time.Instant
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/**
 * Result model for identity queries.
 *
 * Contains all core identity fields plus optional associations that can be
 * populated based on [IdentityFetchOptions].
 *
 * Usage:
 * ```kotlin
 * // Create from entity
 * val result = IdentityResult.from(identity)
 *
 * // Create with associations
 * val resultWithIds = IdentityResult.from(
 *     identity = identity,
 *     identityIdentifiers = listOf(...)
 * )
 * ```
 */
@JsExportCompat
@Serializable
data class IdentityResult
    @JvmOverloads
    constructor(
        /** Party ID - serves as the primary key */
        @SerialName("partyId")
        val partyId: Uuid,
        /** Tenant this identity belongs to */
        @SerialName("tenantId")
        val tenantId: String,
        /** The role of this identity in the credential ecosystem */
        @SerialName("identityRole")
        val identityRole: IdentityRole,
        /** Whether this is the default identity for the owning party */
        @SerialName("isDefault")
        val isDefault: Boolean,
        /**
         * The specialization this identity serves when it is intrinsically role-scoped
         * (null = party-global, fan-out-then-filter applies at login).
         */
        @SerialName("specializationSubtype")
        val specializationSubtype: String? = null,
        /** Controls whether readable profile data may exist on bound Party records. */
        @SerialName("privacyMode")
        val privacyMode: IdentityPrivacyMode = IdentityPrivacyMode.PARTY_PROFILED,
        /** When the identity was created */
        @SerialName("createdAt")
        val createdAt: Instant,
        /** Who created the identity (party ID) */
        @SerialName("createdById")
        val createdById: Uuid? = null,
        /** When the identity was last updated */
        @SerialName("updatedAt")
        val updatedAt: Instant,
        /** Who last updated the identity (party ID) */
        @SerialName("updatedById")
        val updatedById: Uuid? = null,
        /** When the identity was soft-deleted (null if not deleted) */
        @SerialName("deletedAt")
        val deletedAt: Instant? = null,
        /** Who deleted the identity (party ID) */
        @SerialName("deletedById")
        val deletedById: Uuid? = null,
        /**
         * Identity identifiers associated with this identity.
         * Populated when [IdentityFetchOptions.includeIdentityIdentifiers] is true.
         * Null means not fetched (vs empty list which means no identifiers exist).
         */
        @SerialName("identityIdentifiers")
        val identityIdentifiers: List<IdentityIdentifierResult>? = null,
        /**
         * Party bindings associated with this identity.
         * Populated when IdentityFetchOptions.includePartyBindings is true.
         */
        @SerialName("partyBindings")
        val partyBindings: List<IdentityPartyBindingResult>? = null,
        /** Owning Party ID stored on the identity backing Party; null when unowned. */
        @SerialName("ownerId")
        val ownerId: Uuid? = null,
    ) {
        companion object {
            /**
             * Create an IdentityResult from an Identity entity.
             *
             * @param identity The source identity entity
             * @param identityIdentifiers Optional list of identity identifier results
             */
            fun from(
                identity: Identity,
                identityIdentifiers: List<IdentityIdentifierResult>? = null,
                partyBindings: List<IdentityPartyBindingResult>? = null,
            ) = IdentityResult(
                partyId = identity.partyId,
                tenantId = identity.tenantId,
                identityRole = identity.identityRole,
                isDefault = identity.isDefault,
                specializationSubtype = identity.specializationSubtype,
                privacyMode = identity.privacyMode,
                createdAt = identity.createdAt,
                createdById = identity.createdById,
                updatedAt = identity.updatedAt,
                updatedById = identity.updatedById,
                deletedAt = identity.deletedAt,
                deletedById = identity.deletedById,
                identityIdentifiers = identityIdentifiers,
                partyBindings = partyBindings,
            )

            /**
             * Create an IdentityResult from an Identity entity with raw identity identifiers.
             *
             * @param identity The source identity entity
             * @param identityIdentifiers List of identity identifier entities to convert
             */
            fun fromWithIdentifiers(
                identity: Identity,
                identityIdentifiers: List<IdentityIdentifier>,
            ) = from(
                identity = identity,
                identityIdentifiers = identityIdentifiers.map { IdentityIdentifierResult.from(it) },
            )
        }

        /** Convert back to the core Identity entity (without associations) */
        fun toIdentity() =
            Identity(
                partyId = partyId,
                tenantId = tenantId,
                identityRole = identityRole,
                isDefault = isDefault,
                specializationSubtype = specializationSubtype,
                privacyMode = privacyMode,
                createdAt = createdAt,
                createdById = createdById,
                updatedAt = updatedAt,
                updatedById = updatedById,
                deletedAt = deletedAt,
                deletedById = deletedById,
            )
    }
