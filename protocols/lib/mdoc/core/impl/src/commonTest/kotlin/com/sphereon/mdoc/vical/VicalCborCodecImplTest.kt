/*
 * Copyright 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

package com.sphereon.mdoc.vical

import com.sphereon.cbor.Cbor
import com.sphereon.cbor.CborArray
import com.sphereon.cbor.CborByteString
import com.sphereon.cbor.CborMap
import com.sphereon.cbor.CborString
import com.sphereon.cbor.CborTDate
import com.sphereon.cbor.CborUInt
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class VicalCborCodecImplTest {
    private val codec = VicalCborCodecImpl()

    @Test
    fun vical_accepts_zero_issue_id_and_empty_certificate_list() {
        // Annex C permits uint (including zero) and zero CertificateInfo entries.
        val payload = CborMap(
            mutableMapOf(
                CborString("version") to CborString("1.0"),
                CborString("vicalProvider") to CborString("provider"),
                CborString("vicalIssueID") to CborUInt(0),
                CborString("date") to CborTDate("2026-08-27T10:00:00Z"),
                CborString("certificateInfos") to CborArray(mutableListOf()),
            ),
        )

        val decoded = codec.decode(Cbor.encode(payload))

        assertEquals(0uL, decoded.vicalIssueId)
        assertEquals(emptyList(), decoded.certificateInfos)
        assertEquals(decoded, codec.decode(codec.encode(decoded)))
    }

    @Test
    fun vical_round_trips_optional_fields_and_large_serial_number() {
        val expected =
            Vical(
                vicalProvider = "https://vical.example.test/provider",
                vicalIssueId = ULong.MAX_VALUE,
                date = "2026-08-27T10:00:00Z",
                nextUpdate = "2026-08-28T10:00:00Z",
                notAfter = "2026-09-27T10:00:00Z",
                certificateInfos =
                    listOf(
                        VicalCertificateInfo(
                            certificate = byteArrayOf(0x30, 0x01),
                            serialNumber = byteArrayOf(0x80.toByte(), 0, 0, 0, 0, 0, 0, 1),
                            ski = ByteArray(20) { it.toByte() },
                            docTypes = listOf("org.iso.18013.5.1.mDL", "org.example.mDL"),
                            certificateProfiles = listOf("urn:example:IACA", "urn:example:DS"),
                            issuingAuthority = "Example authority",
                            issuingCountry = "NL",
                            stateOrProvinceName = "North Holland",
                            issuer = byteArrayOf(1, 2),
                            subject = byteArrayOf(3, 4),
                            notBefore = "2026-01-01T00:00:00Z",
                            notAfter = "2027-01-01T00:00:00Z",
                            extensions = mapOf("future" to CborString("opaque")),
                        ),
                    ),
                extensions = mapOf("future" to CborUInt(7)),
                vicalUrl = "https://vical.example.test/current.cwt",
            )

        val encoded = codec.encode(expected)
        val decoded = codec.decode(encoded)

        assertEquals(expected.version, decoded.version)
        assertEquals(expected.vicalProvider, decoded.vicalProvider)
        assertEquals(expected.vicalIssueId, decoded.vicalIssueId)
        assertEquals(expected.date, decoded.date)
        assertEquals(expected.nextUpdate, decoded.nextUpdate)
        assertEquals(expected.notAfter, decoded.notAfter)
        assertEquals(expected.docTypes(), decoded.docTypes())
        assertEquals(expected.extensions, decoded.extensions)
        assertEquals(expected.vicalUrl, decoded.vicalUrl)
        assertContentEquals(expected.certificateInfos.single().certificate, decoded.certificateInfos.single().certificate)
        assertContentEquals(expected.certificateInfos.single().serialNumber, decoded.certificateInfos.single().serialNumber)
        assertContentEquals(expected.certificateInfos.single().ski, decoded.certificateInfos.single().ski)
        assertEquals(expected.certificateInfos.single().certificateProfiles, decoded.certificateInfos.single().certificateProfiles)
        assertEquals(expected.certificateInfos.single().extensions, decoded.certificateInfos.single().extensions)
    }

    @Test
    fun vical_rejects_zero_serial_number_and_wrong_date_shape() {
        assertFailsWith<IllegalArgumentException> {
            VicalCertificateInfo(
                certificate = byteArrayOf(1),
                serialNumber = byteArrayOf(0, 0),
                ski = byteArrayOf(1),
                docTypes = listOf("org.iso.18013.5.1.mDL"),
            )
        }

        val invalidDate =
            CborMap(
                mutableMapOf(
                    CborString("version") to CborString("1.0"),
                    CborString("vicalProvider") to CborString("provider"),
                    CborString("date") to CborString("not-a-date"),
                    CborString("certificateInfos") to CborArray(mutableListOf()),
                ),
            )

        assertFailsWith<IllegalArgumentException> {
            codec.decode(Cbor.encode(invalidDate))
        }
    }

    @Test
    fun vical_decoder_rejects_wrong_field_types() {
        val invalid =
            CborMap(
                mutableMapOf(
                    CborString("version") to CborString("1.0"),
                    CborString("vicalProvider") to CborString("provider"),
                    CborString("date") to CborTDate("2026-08-27T10:00:00Z"),
                    CborString("certificateInfos") to CborByteString(byteArrayOf(1)),
                ),
            )

        assertFailsWith<IllegalArgumentException> {
            codec.decode(Cbor.encode(invalid))
        }
    }

    private fun Vical.docTypes(): List<String> = certificateInfos.flatMap { it.docTypes }

    @Test
    fun certificateProfilesRequireUrnSyntax() {
        val entry = VicalCertificateInfo(byteArrayOf(1), byteArrayOf(1), byteArrayOf(1), listOf("org.example.mdoc"))
        for (profile in listOf("IACA", "https://example.test/profile", "urn:x:a", "urn:example:", "urn:example:bad value", "urn:example:bad%2")) {
            assertFailsWith<IllegalArgumentException>(profile) { entry.copy(certificateProfiles = listOf(profile)) }
        }
        for (profile in listOf("urn:example:iaca", "URN:example:with%20encoding", "urn:example:profile/path?+resolve?=query#fragment")) {
            assertEquals(listOf(profile), entry.copy(certificateProfiles = listOf(profile)).certificateProfiles)
        }
    }
}
