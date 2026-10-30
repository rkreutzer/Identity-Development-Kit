/*
 * Copyright 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

package com.sphereon.wallet.interaction.protocol.oid4vp

import com.sphereon.cbor.tDateToEpochSeconds
import com.sphereon.core.api.decodeFromBase64Url
import com.sphereon.core.compat.DateTimeUtils
import com.sphereon.mdoc.data.device.IssuerSignedCborCodecImpl
import com.sphereon.mdoc.data.mso.MobileSecurityObjectCborCodecImpl
import com.sphereon.wallet.credential.CredentialFormat
import com.sphereon.wallet.credential.CredentialInstance
import com.sphereon.wallet.credential.CredentialLifecycleState
import com.sphereon.wallet.credential.CredentialRecord
import com.sphereon.wallet.credential.CredentialValidityState
import com.sphereon.wallet.credential.CredentialValidityWindow
import kotlin.time.Instant

private val issuerSignedCodec = IssuerSignedCborCodecImpl()
private val mobileSecurityObjectCodec = MobileSecurityObjectCborCodecImpl()

/**
 * Select from concrete instances, not the record's aggregate validity. Legacy mdoc records may
 * have UNKNOWN persisted validity even though their MSO carries the required signed validityInfo.
 */
internal fun CredentialRecord.presentableOid4vpInstance(now: Instant): CredentialInstance? =
    instances.firstOrNull { it.isPresentableOid4vpInstance(now) }

internal fun CredentialInstance.isPresentableOid4vpInstance(now: Instant): Boolean {
    if (lifecycleState != CredentialLifecycleState.ACTIVE) return false
    if (!format.isMdoc) {
        val state = validity.stateAt(now)
        return state != CredentialValidityState.NOT_YET_VALID && state != CredentialValidityState.EXPIRED
    }
    val storedState = validity.stateAt(now)
    if (storedState == CredentialValidityState.NOT_YET_VALID || storedState == CredentialValidityState.EXPIRED) return false

    return mdocValidityStateAt(now) == CredentialValidityState.VALID
}

private fun CredentialInstance.mdocValidityStateAt(now: Instant): CredentialValidityState? =
    runCatching {
        val rawCredential = raw ?: return null
        val issuerSignedBytes = rawCredential.decodeFromBase64Url()
        val issuerSigned = issuerSignedCodec.decode(issuerSignedBytes).getOrNull()?.value ?: return null
        val msoPayload = issuerSigned.issuerAuth.payload?.value ?: return null
        val mso = mobileSecurityObjectCodec.decode(msoPayload).getOrNull()?.value ?: return null
        val validityInfo = mso.validityInfo
        CredentialValidityWindow(
            validFrom = Instant.fromEpochSeconds(validityInfo.validFrom.tDateToEpochSeconds(DateTimeUtils.DEFAULTS)),
            validUntil = Instant.fromEpochSeconds(validityInfo.validUntil.tDateToEpochSeconds(DateTimeUtils.DEFAULTS)),
        ).stateAt(now)
    }.getOrNull()
