/*
 * Copyright 2023-2026 Sphereon International B.V.
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
 */

package com.sphereon.sdjwt.vc

import com.sphereon.core.api.encodeToBase64
import com.sphereon.crypto.core.generic.DigestAlg
import com.sphereon.crypto.core.generic.hash
import kotlin.test.Test
import kotlin.test.assertTrue

class TypeMetadataIntegrityTest {
    private val document = """{ "vct": "https://example.org/pid" }""".encodeToByteArray()

    private fun sri(
        prefix: String,
        algorithm: DigestAlg,
        content: ByteArray = document,
    ) = "$prefix-" + hash(content, algorithm).encodeToBase64()

    private fun accepts(integrity: String) = TypeMetadataIntegrity.verify(document, integrity).isOk

    @Test
    fun shouldAcceptAMatchingSha256Digest() {
        assertTrue(accepts(sri("sha256", DigestAlg.SHA256)))
    }

    @Test
    fun shouldAcceptAMatchingSha384Digest() {
        assertTrue(accepts(sri("sha384", DigestAlg.SHA384)))
    }

    @Test
    fun shouldAcceptAMatchingSha512Digest() {
        assertTrue(accepts(sri("sha512", DigestAlg.SHA512)))
    }

    @Test
    fun shouldRefuseAMismatchingDigest() {
        assertTrue(TypeMetadataIntegrity.verify(document, sri("sha256", DigestAlg.SHA256, "other".encodeToByteArray())).isErr)
    }

    @Test
    fun shouldRefuseADocumentWhoseWhitespaceDiffersFromThePinnedOctets() {
        val pinned = sri("sha256", DigestAlg.SHA256, """{"vct":"https://example.org/pid"}""".encodeToByteArray())

        assertTrue(TypeMetadataIntegrity.verify(document, pinned).isErr)
    }

    @Test
    fun shouldAcceptWhenOneExpressionOfTheStrongestAlgorithmMatches() {
        val wrong = sri("sha512", DigestAlg.SHA512, "other".encodeToByteArray())

        assertTrue(accepts("$wrong ${sri("sha512", DigestAlg.SHA512)}"))
    }

    @Test
    fun shouldRefuseWhenTheStrongestAlgorithmMismatchesEvenIfAWeakerOneMatches() {
        val wrongStrong = sri("sha512", DigestAlg.SHA512, "other".encodeToByteArray())

        assertTrue(TypeMetadataIntegrity.verify(document, "$wrongStrong ${sri("sha256", DigestAlg.SHA256)}").isErr)
    }

    @Test
    fun shouldIgnoreAnUnsupportedAlgorithmBesideASupportedOne() {
        assertTrue(accepts("md5-AAAA ${sri("sha256", DigestAlg.SHA256)}"))
    }

    @Test
    fun shouldRefuseWhenOnlyUnsupportedAlgorithmsArePresent() {
        assertTrue(TypeMetadataIntegrity.verify(document, "md5-AAAA").isErr)
    }

    @Test
    fun shouldRefuseAnEmptyExpression() {
        assertTrue(TypeMetadataIntegrity.verify(document, "   ").isErr)
    }

    @Test
    fun shouldRefuseAMalformedExpressionWithoutADigest() {
        assertTrue(TypeMetadataIntegrity.verify(document, "sha256-").isErr)
    }

    @Test
    fun shouldRefuseAMalformedExpressionWithoutAnAlgorithm() {
        assertTrue(TypeMetadataIntegrity.verify(document, "-abcd").isErr)
    }

    @Test
    fun shouldRefuseAnExpressionWithoutASeparator() {
        assertTrue(TypeMetadataIntegrity.verify(document, "sha256").isErr)
    }

    @Test
    fun shouldIgnoreOptionsAfterTheDigest() {
        assertTrue(accepts(sri("sha256", DigestAlg.SHA256) + "?ct=application/json"))
    }

    @Test
    fun shouldAcceptAnUppercaseAlgorithmName() {
        assertTrue(accepts(sri("SHA256", DigestAlg.SHA256)))
    }
}
