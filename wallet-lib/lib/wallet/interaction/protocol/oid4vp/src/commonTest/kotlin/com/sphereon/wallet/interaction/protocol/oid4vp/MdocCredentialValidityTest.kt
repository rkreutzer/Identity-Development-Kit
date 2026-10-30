/*
 * Copyright 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

package com.sphereon.wallet.interaction.protocol.oid4vp

import com.sphereon.data.store.party.model.IdentifierType
import com.sphereon.wallet.credential.CredentialFormat
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
import com.sphereon.wallet.credential.KeyRef
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Instant

class MdocCredentialValidityTest {
    @Test
    fun legacyUnknownExpiredInstanceIsSkippedForFreshValidInstance() {
        val now = Instant.fromEpochSeconds(1_800_000_000)
        val oldRaw = mdocCredential("2025-01-20T12:00:00Z", "2026-01-20T12:00:00Z")
        val newRaw = mdocCredential("2026-01-20T12:00:00Z", "2028-01-20T12:00:00Z")
        val record =
            record(
                instance("old-expired", oldRaw),
                instance("new-valid", newRaw),
            )

        val selected = record.presentableOid4vpInstance(now)

        assertEquals("new-valid", selected?.id)
        assertEquals("key-new-valid", selected?.holderKeyRef?.alias)
        assertEquals(newRaw, selected?.raw)
    }

    @Test
    fun unknownLegacyWindowUsesMsoDatesAndFailsClosedForExpiredFutureOrMalformedMdoc() {
        val now = Instant.fromEpochSeconds(1_800_000_000)

        val expired = instance("expired", mdocCredential("2025-01-20T12:00:00Z", "2026-01-20T12:00:00Z"))
        assertFalse(expired.isPresentableOid4vpInstance(now))
        assertNull(record(expired).presentableOid4vpInstance(now))
        assertFalse(instance("future", mdocCredential("2028-01-20T12:00:00Z", "2029-01-20T12:00:00Z")).isPresentableOid4vpInstance(now))
        assertFalse(instance("malformed", "not-cbor").isPresentableOid4vpInstance(now))
        assertTrue(instance("valid", mdocCredential("2026-01-20T12:00:00Z", "2028-01-20T12:00:00Z")).isPresentableOid4vpInstance(now))

        val msoValid = mdocCredential("2026-01-20T12:00:00Z", "2028-01-20T12:00:00Z")
        assertFalse(
            instance(
                "stored-expired",
                msoValid,
                validity = CredentialValidityWindow(validUntil = Instant.fromEpochSeconds(1_700_000_000)),
            ).isPresentableOid4vpInstance(now),
        )
        assertFalse(
            instance(
                "stored-future",
                msoValid,
                validity = CredentialValidityWindow(validFrom = Instant.fromEpochSeconds(1_900_000_000)),
            ).isPresentableOid4vpInstance(now),
        )
    }

    private fun record(vararg instances: CredentialInstance): CredentialRecord {
        val now = Instant.fromEpochSeconds(1_800_000_000)
        return CredentialRecord(
            id = "record",
            walletUnitId = "wallet",
            issuerRef = IdentifierRef(IdentifierType("https"), "https://issuer.example"),
            format = CredentialFormat.MSO_MDOC,
            credentialTypeRefs =
                setOf(
                    CredentialTypeRef(
                        format = CredentialFormat.MSO_MDOC,
                        kind = CredentialTypeRefKind.MDOC_DOCTYPE,
                        value = "eu.europa.ec.eudi.pid.1",
                        source = CredentialTypeRefSource.CREDENTIAL_PAYLOAD,
                        primary = true,
                    ),
                ),
            instances = instances.toList(),
            createdAt = now,
            updatedAt = now,
        )
    }

    private fun instance(
        id: String,
        raw: String,
        validity: CredentialValidityWindow = CredentialValidityWindow(),
    ): CredentialInstance {
        val now = Instant.fromEpochSeconds(1_800_000_000)
        return CredentialInstance(
            id = id,
            walletUnitId = "wallet",
            credentialRecordId = "record",
            format = CredentialFormat.MSO_MDOC,
            raw = raw,
            holderKeyRef = KeyRef(alias = "key-$id"),
            bodyStorageRef = BodyStorageRef(BodyStorageKind.WALLET_STORE, "wallet/$id/body"),
            lifecycleState = CredentialLifecycleState.ACTIVE,
            validity = validity,
            storedAt = now,
            updatedAt = now,
        )
    }
}
