/*
 * Copyright 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

package com.sphereon.wallet.interaction.protocol.oid4vp

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.error.IdkError
import com.sphereon.credential.claims.mapper.api.mapper.ClaimsMappingService
import com.sphereon.credential.claims.mapper.api.model.ClaimMappingConfiguration
import com.sphereon.credential.claims.mapper.api.model.CredentialWithId
import com.sphereon.credential.claims.mapper.api.model.MappedClaimsResult
import com.sphereon.data.store.party.model.IdentifierType
import com.sphereon.openid.oid4vc.common.CredentialFormat
import com.sphereon.wallet.credential.BodyStorageKind
import com.sphereon.wallet.credential.BodyStorageRef
import com.sphereon.wallet.credential.CredentialInstance
import com.sphereon.wallet.credential.CredentialLifecycleState
import com.sphereon.wallet.credential.CredentialRecord
import com.sphereon.wallet.credential.CredentialTypeRef
import com.sphereon.wallet.credential.CredentialTypeRefKind
import com.sphereon.wallet.credential.CredentialTypeRefSource
import com.sphereon.wallet.credential.CredentialValidityWindow
import com.sphereon.wallet.credential.IdentifierRef
import kotlinx.serialization.json.JsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Clock

class WalletCredentialClaimValuesResolverTest {
    @Test
    fun projectsTypedResolverValuesForThePresentableRecordInstance() = kotlinx.coroutines.test.runTest {
        val mapping = RecordingClaimsMappingService()
        val resolver = WalletCredentialClaimValuesResolver(mapping)
        val rawMdoc = mdocCredential("2020-01-20T12:00:00Z", "2099-12-31T23:59:59Z")
        val record = record(CredentialFormat.MSO_MDOC, rawMdoc)
        val values = mapOf("org.iso.18013.5.1.family_name" to JsonPrimitive("Lindgren"))
        mapping.result = values

        val result = resolver.resolve(record)

        assertTrue(result.isOk)
        assertEquals(values, result.value)
        assertEquals("instance-active", mapping.credential?.credentialId)
        assertEquals(CredentialFormat.MSO_MDOC, mapping.credential?.format)
        assertEquals(rawMdoc, mapping.credential?.payload)
    }

    @Test
    fun projectsTheSameFreshMdocInstanceSelectedForPresentation() = kotlinx.coroutines.test.runTest {
        val mapping = RecordingClaimsMappingService()
        val resolver = WalletCredentialClaimValuesResolver(mapping)
        val old = instance("instance-expired", mdocCredential("2025-01-20T12:00:00Z", "2026-01-20T12:00:00Z"), CredentialLifecycleState.ACTIVE, CredentialFormat.MSO_MDOC)
        val freshRaw = mdocCredential("2026-01-20T12:00:00Z", "2099-12-31T23:59:59Z")
        val fresh = instance("instance-fresh", freshRaw, CredentialLifecycleState.ACTIVE, CredentialFormat.MSO_MDOC)
        val record = record(CredentialFormat.MSO_MDOC, old.requireRaw()).copy(instances = listOf(old, fresh))
        mapping.result = emptyMap()

        val result = resolver.resolve(record)

        assertTrue(result.isOk)
        assertEquals("instance-fresh", mapping.credential?.credentialId)
        assertEquals(freshRaw, mapping.credential?.payload)
    }

    @Test
    fun canProjectAnExactActiveInstanceAndKeepsSdJwtValuesTyped() = kotlinx.coroutines.test.runTest {
        val mapping = RecordingClaimsMappingService()
        val resolver = WalletCredentialClaimValuesResolver(mapping)
        val record =
            record(CredentialFormat.SD_JWT_VC, "active-body").copy(
                instances =
                    listOf(
                        instance("instance-old", "superseded-body", CredentialLifecycleState.SUPERSEDED, CredentialFormat.SD_JWT_VC),
                        instance("instance-current", "active-body", CredentialLifecycleState.ACTIVE, CredentialFormat.SD_JWT_VC),
                    ),
            )
        val values = mapOf("age_over_18" to JsonPrimitive(true), "address.postal_code" to JsonPrimitive("1234 AB"))
        mapping.result = values

        val result = resolver.resolve(record, "instance-current")

        assertTrue(result.isOk)
        assertEquals(values, result.value)
        assertEquals("instance-current", mapping.credential?.credentialId)
        assertEquals("active-body", mapping.credential?.payload)
        assertFalse(mapping.credential?.payload?.contains("address.postal_code") == true)
    }

    @Test
    fun refusesSupersededInstancesBeforeCallingTheClaimResolver() = kotlinx.coroutines.test.runTest {
        val mapping = RecordingClaimsMappingService()
        val resolver = WalletCredentialClaimValuesResolver(mapping)
        val record = record(CredentialFormat.SD_JWT_VC, "old-body").copy(
            instances = listOf(instance("instance-old", "old-body", CredentialLifecycleState.SUPERSEDED, CredentialFormat.SD_JWT_VC)),
        )

        val result = resolver.resolve(record, "instance-old")

        assertTrue(result.isErr)
        assertEquals(null, mapping.credential)
    }

    private fun record(format: CredentialFormat, raw: String): CredentialRecord =
        CredentialRecord(
            id = "record-opaque",
            walletUnitId = "profile-wallet",
            issuerRef = IdentifierRef(IdentifierType("https"), "https://issuer.example"),
            format = format,
            credentialTypeRefs =
                setOf(
                    CredentialTypeRef(
                        format = format,
                        kind = if (format == CredentialFormat.MSO_MDOC) CredentialTypeRefKind.MDOC_DOCTYPE else CredentialTypeRefKind.SD_JWT_VCT,
                        value = "type-ref",
                        source = CredentialTypeRefSource.CREDENTIAL_PAYLOAD,
                    ),
                ),
            instances = listOf(instance("instance-active", raw, CredentialLifecycleState.ACTIVE, format)),
            createdAt = Clock.System.now(),
            updatedAt = Clock.System.now(),
        )

    private fun instance(id: String, raw: String, lifecycle: CredentialLifecycleState, format: CredentialFormat): CredentialInstance {
        val now = Clock.System.now()
        return CredentialInstance(
            id = id,
            walletUnitId = "profile-wallet",
            credentialRecordId = "record-opaque",
            format = format,
            raw = raw,
            bodyStorageRef = BodyStorageRef(BodyStorageKind.WALLET_STORE, "wallet/$id/body"),
            lifecycleState = lifecycle,
            validity = CredentialValidityWindow(),
            storedAt = now,
            updatedAt = now,
        )
    }

    private class RecordingClaimsMappingService : ClaimsMappingService {
        var credential: CredentialWithId? = null
        var result: Map<String, kotlinx.serialization.json.JsonElement> = emptyMap()

        override suspend fun mapClaimsWithConfig(
            credentials: List<CredentialWithId>,
            config: ClaimMappingConfiguration,
        ): IdkResult<MappedClaimsResult, IdkError> = error("not used")

        override suspend fun extractAllClaims(credential: CredentialWithId): IdkResult<Map<String, kotlinx.serialization.json.JsonElement>, IdkError> {
            this.credential = credential
            return Ok(result).asResult()
        }
    }
}
