/* Copyright 2026 Sphereon International B.V. Licensed under the Apache License, Version 2.0. */
package com.sphereon.openid.oid4vp.verifier.impl

import com.sphereon.crypto.resolution.extern.ExternalIdentifierDidOpts
import com.sphereon.crypto.resolution.extern.ExternalIdentifierX5cOpts
import com.sphereon.openid.oid4vp.verifier.TrustedAuthenticationPurpose
import com.sphereon.openid.oid4vp.verifier.TrustedAuthenticationResolution
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class MdocStatusTrustAnchorsTest {
    private fun issuer(controller: String, vararg x5c: String) =
        TrustedAuthenticationResolution(controller, ExternalIdentifierX5cOpts(x5c.toList()), purpose = TrustedAuthenticationPurpose.CREDENTIAL_ISSUER)

    @Test
    fun documentTypeRestrictionsRemainSeparateBetweenDocuments() {
        val sources = listOf(
            issuer("mdl", "root-mdl").copy(documentTypes = setOf("org.iso.18013.5.1.mDL")),
            issuer("pid", "root-pid").copy(documentTypes = setOf("eu.europa.ec.eudi.pid.1")),
            issuer("removed", "root-removed").copy(documentTypes = emptySet()),
        )
        assertEquals(listOf("root-mdl"), mdocStatusTrustAnchors(sources, "org.iso.18013.5.1.mDL"))
        assertEquals(listOf("root-pid"), mdocStatusTrustAnchors(sources, "eu.europa.ec.eudi.pid.1"))
        assertEquals(emptyList(), mdocStatusTrustAnchors(sources, "unknown"))
        assertEquals(emptyList(), mdocStatusTrustAnchors(sources))
        assertEquals(listOf("static"), mdocStatusTrustAnchors(sources + issuer("static", "static"), "unknown"))
    }

    @Test
    fun onlyCredentialIssuerX509EvidenceSuppliesStatusRoots() {
        val anchors = mdocStatusTrustAnchors(
            listOf(
                issuer("issuer-a", "root-a", "intermediate-a"),
                TrustedAuthenticationResolution("holder", ExternalIdentifierX5cOpts(listOf("holder-root")), purpose = TrustedAuthenticationPurpose.HOLDER),
                TrustedAuthenticationResolution("did-issuer", ExternalIdentifierDidOpts("did:example:issuer"), purpose = TrustedAuthenticationPurpose.CREDENTIAL_ISSUER),
                issuer("issuer-b", "root-a", "root-b"),
            ),
        )

        assertEquals(listOf("root-a", "intermediate-a", "root-b"), anchors)
    }

    @Test
    fun noX509IssuerEvidenceLeavesTheStatusVerifierOnItsOwnRoots() {
        assertNull(mdocStatusTrustAnchors(emptyList()))
        assertNull(
            mdocStatusTrustAnchors(
                listOf(
                    TrustedAuthenticationResolution("holder", ExternalIdentifierX5cOpts(listOf("holder-root")), purpose = TrustedAuthenticationPurpose.HOLDER),
                    TrustedAuthenticationResolution("did-issuer", ExternalIdentifierDidOpts("did:example:issuer"), purpose = TrustedAuthenticationPurpose.CREDENTIAL_ISSUER),
                ),
            ),
        )
    }
}
