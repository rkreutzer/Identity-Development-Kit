/*
 * Copyright (c) 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

package com.sphereon.crypto.kms.rest.server.service

import com.sphereon.crypto.core.kms.X509CertificateExtensionSpec

/**
 * Builds the small, typed extension set exposed by the KMS certificate issuance API.
 *
 * Arbitrary extension DER is deliberately not accepted from REST callers.
 */
internal object CertificateIssuanceExtensions {
    private const val BASIC_CONSTRAINTS_OID = "2.5.29.19"
    private const val KEY_USAGE_OID = "2.5.29.15"

    private const val DIGITAL_SIGNATURE = "digitalSignature"
    private const val KEY_CERT_SIGN = "keyCertSign"
    private const val CRL_SIGN = "cRLSign"
    private val supportedUsages = setOf(DIGITAL_SIGNATURE, KEY_CERT_SIGN, CRL_SIGN)

    fun create(
        certificateAuthorityPathLengthConstraint: Int?,
        keyUsage: List<String>?,
    ): List<X509CertificateExtensionSpec> {
        val requestedUsages = keyUsage.orEmpty()
        require(requestedUsages.distinct().size == requestedUsages.size) {
            "Certificate keyUsage values must be unique"
        }
        require(requestedUsages.all { it in supportedUsages }) {
            "Certificate keyUsage contains an unsupported value"
        }
        require(certificateAuthorityPathLengthConstraint == null || certificateAuthorityPathLengthConstraint >= 0) {
            "Certificate authority path length must be non-negative"
        }
        require(certificateAuthorityPathLengthConstraint != null || requestedUsages.none { it == KEY_CERT_SIGN || it == CRL_SIGN }) {
            "keyCertSign and cRLSign require a certificate authority path-length constraint"
        }

        val extensions = mutableListOf<X509CertificateExtensionSpec>()
        if (certificateAuthorityPathLengthConstraint != null) {
            extensions +=
                X509CertificateExtensionSpec(
                    oid = BASIC_CONSTRAINTS_OID,
                    critical = true,
                    valueDer = encodeBasicConstraints(certificateAuthorityPathLengthConstraint),
                )
        }

        val encodedUsages =
            buildSet {
                addAll(requestedUsages)
                if (certificateAuthorityPathLengthConstraint != null) {
                    add(KEY_CERT_SIGN)
                    add(CRL_SIGN)
                }
            }
        if (encodedUsages.isNotEmpty()) {
            extensions +=
                X509CertificateExtensionSpec(
                    oid = KEY_USAGE_OID,
                    critical = true,
                    valueDer = encodeKeyUsage(encodedUsages),
                )
        }
        return extensions
    }

    private fun encodeBasicConstraints(pathLength: Int): ByteArray {
        val encodedPathLength = encodeInteger(pathLength)
        return encodeDer(
            tag = 0x30,
            value = byteArrayOf(0x01, 0x01, 0xff.toByte()) + encodedPathLength,
        )
    }

    private fun encodeInteger(value: Int): ByteArray {
        require(value >= 0) { "DER integer must be non-negative" }
        val bytes = mutableListOf<Byte>()
        var remaining = value
        do {
            bytes.add(0, (remaining and 0xff).toByte())
            remaining = remaining ushr 8
        } while (remaining != 0)
        if (bytes.first().toInt() and 0x80 != 0) bytes.add(0, 0)
        return encodeDer(0x02, bytes.toByteArray())
    }

    private fun encodeKeyUsage(usages: Set<String>): ByteArray {
        var bits = 0
        if (DIGITAL_SIGNATURE in usages) bits = bits or 0x80
        if (KEY_CERT_SIGN in usages) bits = bits or 0x04
        if (CRL_SIGN in usages) bits = bits or 0x02
        val unusedBits =
            when {
                bits and 0x01 != 0 -> 0
                bits and 0x02 != 0 -> 1
                bits and 0x04 != 0 -> 2
                bits and 0x08 != 0 -> 3
                bits and 0x10 != 0 -> 4
                bits and 0x20 != 0 -> 5
                bits and 0x40 != 0 -> 6
                else -> 7
            }
        return encodeDer(0x03, byteArrayOf(unusedBits.toByte(), bits.toByte()))
    }

    private fun encodeDer(tag: Int, value: ByteArray): ByteArray {
        require(value.size < 128) { "Certificate extension is unexpectedly large" }
        return byteArrayOf(tag.toByte(), value.size.toByte()) + value
    }
}
