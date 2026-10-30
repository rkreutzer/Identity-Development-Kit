/*
 * Copyright (c) 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

package com.sphereon.crypto.kms.rest.server.service

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class CertificateIssuanceExtensionsTest {
    @Test
    fun certificateAuthorityHasCriticalBasicConstraintsAndSigningUsages() {
        val extensions = CertificateIssuanceExtensions.create(certificateAuthorityPathLengthConstraint = 0, keyUsage = null)

        assertEquals(listOf("2.5.29.19", "2.5.29.15"), extensions.map { it.oid })
        assertEquals(listOf(true, true), extensions.map { it.critical })
        assertContentEquals(byteArrayOf(0x30, 0x06, 0x01, 0x01, 0xff.toByte(), 0x02, 0x01, 0x00), extensions[0].valueDer)
        assertContentEquals(byteArrayOf(0x03, 0x02, 0x01, 0x06), extensions[1].valueDer)
    }

    @Test
    fun nonCaCanRequestOnlySupportedLeafUsages() {
        val extensions = CertificateIssuanceExtensions.create(null, listOf("digitalSignature"))

        assertEquals(listOf("2.5.29.15"), extensions.map { it.oid })
        assertContentEquals(byteArrayOf(0x03, 0x02, 0x07, 0x80.toByte()), extensions.single().valueDer)
    }

    @Test
    fun certificateAuthorityPathLengthUsesMinimalPositiveIntegerEncoding() {
        val extension = CertificateIssuanceExtensions.create(128, null).first()

        assertContentEquals(
            byteArrayOf(0x30, 0x07, 0x01, 0x01, 0xff.toByte(), 0x02, 0x02, 0x00, 0x80.toByte()),
            extension.valueDer,
        )
    }

    @Test
    fun nonCaRejectsCertificateSigningUsages() {
        assertFailsWith<IllegalArgumentException> {
            CertificateIssuanceExtensions.create(null, listOf("keyCertSign"))
        }
        assertFailsWith<IllegalArgumentException> {
            CertificateIssuanceExtensions.create(null, listOf("cRLSign"))
        }
    }

    @Test
    fun rejectsDuplicateUnsupportedAndNegativeValues() {
        assertFailsWith<IllegalArgumentException> {
            CertificateIssuanceExtensions.create(null, listOf("digitalSignature", "digitalSignature"))
        }
        assertFailsWith<IllegalArgumentException> {
            CertificateIssuanceExtensions.create(null, listOf("keyAgreement"))
        }
        assertFailsWith<IllegalArgumentException> {
            CertificateIssuanceExtensions.create(-1, null)
        }
    }
}
