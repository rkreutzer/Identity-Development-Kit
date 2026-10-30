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

package com.sphereon.openid.oid4vp.verifier.impl

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.error.IdkError
import com.sphereon.jsonld.JsonLdError
import com.sphereon.jsonld.LinkedDataDocument
import com.sphereon.jsonld.loader.BuiltInContextLinkedDataDocumentLoader
import com.sphereon.jsonld.loader.DefaultBuiltInContextRegistry
import com.sphereon.jsonld.loader.LinkedDataDocumentLoader
import com.sphereon.openid.oid4vp.dcql.DcqlCredentialQuery
import com.sphereon.openid.oid4vp.verifier.impl.testutil.CountingTypeMetadataCommand
import com.sphereon.openid.oid4vp.verifier.impl.testutil.testCredentialTypeMatcher
import com.sphereon.sdjwt.vc.SdJwtVcTypeMetadata
import com.sphereon.sdjwt.vc.StaticTypeMetadataResolver
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class CredentialTypeMatcherImplTest {
    private val vcdm11 = "https://www.w3.org/2018/credentials/v1"
    private val examples = "https://www.w3.org/2018/credentials/examples/v1"
    private val verifiableCredential = "https://www.w3.org/2018/credentials#VerifiableCredential"
    private val universityDegree = "https://example.org/examples#UniversityDegreeCredential"

    private class CountingLoader(
        private val served: Map<String, JsonElement>,
        private val fallback: LinkedDataDocumentLoader,
    ) : LinkedDataDocumentLoader {
        val requested = mutableListOf<String>()

        override suspend fun loadDocument(iri: String): IdkResult<LinkedDataDocument, JsonLdError> {
            requested += iri
            return served[iri]?.let { Ok(LinkedDataDocument(iri, it)) } ?: fallback.loadDocument(iri)
        }
    }

    private val examplesContext: JsonElement =
        buildJsonObject { putJsonObject("@context") { put("@vocab", "https://example.org/examples#") } }

    private val builtIn = BuiltInContextLinkedDataDocumentLoader(DefaultBuiltInContextRegistry())

    private fun loader() = CountingLoader(mapOf(examples to examplesContext), builtIn)

    private val unreachable =
        LinkedDataDocumentLoader { iri -> Err(JsonLdError.LoadingDocumentFailed(iri, "context server is down")) }

    private fun query(
        format: String,
        vararg alternatives: List<String>,
    ) = DcqlCredentialQuery(
        id = "q",
        format = format,
        meta =
            buildJsonObject {
                putJsonArray("type_values") { alternatives.forEach { add(JsonArray(it.map(::JsonPrimitive))) } }
            },
    )

    private fun sdJwtQuery(vararg vcts: String) =
        DcqlCredentialQuery(
            id = "q",
            format = "dc+sd-jwt",
            meta = buildJsonObject { putJsonArray("vct_values") { vcts.forEach { add(JsonPrimitive(it)) } } },
        )

    private fun credential(
        types: List<String>,
        vararg contexts: String,
        subject: JsonObject? = null,
    ) = buildJsonObject {
        if (contexts.isNotEmpty()) putJsonArray("@context") { contexts.forEach { add(JsonPrimitive(it)) } }
        putJsonArray("type") { types.forEach { add(JsonPrimitive(it)) } }
        put("credentialSubject", subject ?: buildJsonObject { put("id", "did:example:holder") })
    }

    private suspend fun matches(
        credential: JsonObject,
        query: DcqlCredentialQuery,
        loader: LinkedDataDocumentLoader = loader(),
    ) = testCredentialTypeMatcher(documentLoader = loader).matches(credential, query)

    private fun IdkResult<Boolean, IdkError>.accepted(): Boolean {
        assertTrue(isOk, "expected Ok but was ${errorOrNull()?.message?.defaultMessage}")
        return getOrNull() == true
    }

    @Test
    fun shouldMatchTheUniversityDegreeExampleForJwtVcJson() =
        runTest {
            val result =
                matches(
                    credential(listOf("VerifiableCredential", "UniversityDegreeCredential"), vcdm11, examples),
                    query("jwt_vc_json", listOf(verifiableCredential, universityDegree)),
                )

            assertTrue(result.accepted())
        }

    @Test
    fun shouldMatchTheUniversityDegreeExampleForLdpVc() =
        runTest {
            val result =
                matches(
                    credential(listOf("VerifiableCredential", "UniversityDegreeCredential"), vcdm11, examples),
                    query("ldp_vc", listOf(verifiableCredential, universityDegree)),
                )

            assertTrue(result.accepted())
        }

    @Test
    fun shouldKeepAnUndefinedTypeAsWritten() =
        runTest {
            val loader = loader()

            val result = matches(credential(listOf("IdentityCredential")), query("jwt_vc_json", listOf("IdentityCredential")), loader)

            assertTrue(result.accepted())
            assertTrue(loader.requested.isEmpty())
        }

    @Test
    fun shouldKeepAnUndefinedTypeAsWrittenForLdpVc() =
        runTest {
            val result =
                matches(credential(listOf("VerifiableCredential", "IdentityCredential"), vcdm11), query("ldp_vc", listOf("IdentityCredential")))

            assertTrue(result.accepted())
        }

    @Test
    fun shouldRefuseTheShortNameOfADefinedType() =
        runTest {
            val result =
                matches(
                    credential(listOf("VerifiableCredential", "UniversityDegreeCredential"), vcdm11, examples),
                    query("jwt_vc_json", listOf("VerifiableCredential", "UniversityDegreeCredential")),
                )

            assertFalse(result.accepted())
        }

    @Test
    fun shouldRefuseACredentialOfAnotherType() =
        runTest {
            val result =
                matches(
                    credential(listOf("VerifiableCredential", "OtherCredential"), vcdm11, examples),
                    query("jwt_vc_json", listOf(verifiableCredential, universityDegree)),
                )

            assertFalse(result.accepted())
        }

    @Test
    fun shouldAcceptWhenOnlyTheSecondAlternativeMatches() =
        runTest {
            val result =
                matches(
                    credential(listOf("VerifiableCredential", "UniversityDegreeCredential"), vcdm11, examples),
                    query("jwt_vc_json", listOf("Unrelated"), listOf(verifiableCredential, universityDegree)),
                )

            assertTrue(result.accepted())
        }

    @Test
    fun shouldRefuseAnAlternativeThatIsOnlyPartiallyPresent() =
        runTest {
            val result =
                matches(
                    credential(listOf("VerifiableCredential"), vcdm11),
                    query("jwt_vc_json", listOf(verifiableCredential, universityDegree)),
                )

            assertFalse(result.accepted())
        }

    @Test
    fun shouldAllowExtraAndReorderedCredentialTypes() =
        runTest {
            val result =
                matches(
                    credential(listOf("UniversityDegreeCredential", "Extra", "VerifiableCredential"), vcdm11, examples),
                    query("ldp_vc", listOf(universityDegree, verifiableCredential)),
                )

            assertTrue(result.accepted())
        }

    @Test
    fun shouldNotCombineAlternativesToSatisfyOne() =
        runTest {
            val result =
                matches(
                    credential(listOf("VerifiableCredential"), vcdm11),
                    query("jwt_vc_json", listOf(verifiableCredential, universityDegree), listOf(universityDegree)),
                )

            assertFalse(result.accepted())
        }

    @Test
    fun shouldFailWhenAContextCannotBeLoadedEvenIfTheLiteralTypeWouldMatch() =
        runTest {
            val result =
                matches(
                    credential(listOf("UniversityDegreeCredential"), "https://example.org/unreachable/v1"),
                    query("jwt_vc_json", listOf("UniversityDegreeCredential")),
                    unreachable,
                )

            assertTrue(result.isErr)
        }

    @Test
    fun shouldNotLetASubjectTypeMakeTheCredentialMatch() =
        runTest {
            val result =
                matches(
                    credential(
                        listOf("VerifiableCredential"),
                        vcdm11,
                        examples,
                        subject = buildJsonObject { put("type", "UniversityDegreeCredential") },
                    ),
                    query("jwt_vc_json", listOf(universityDegree)),
                )

            assertFalse(result.accepted())
        }

    @Test
    fun shouldExpandTypesGivenAsASingleString() =
        runTest {
            val document =
                buildJsonObject {
                    putJsonArray("@context") { add(JsonPrimitive(vcdm11)); add(JsonPrimitive(examples)) }
                    put("type", "UniversityDegreeCredential")
                }

            assertTrue(matches(document, query("jwt_vc_json", listOf(universityDegree))).accepted())
        }

    @Test
    fun shouldFailWhenTheCredentialHasNoType() =
        runTest {
            val result = matches(buildJsonObject { put("credentialSubject", buildJsonObject { }) }, query("jwt_vc_json", listOf("A")))

            assertTrue(result.isErr)
        }

    @Test
    fun shouldFailWhenTheTypesAreEmpty() =
        runTest {
            assertTrue(matches(credential(emptyList(), vcdm11), query("jwt_vc_json", listOf("A"))).isErr)
        }

    @Test
    fun shouldFailWhenATypeIsNotAString() =
        runTest {
            val document = buildJsonObject { put("type", buildJsonArray { add(JsonPrimitive(1)) }) }

            assertTrue(matches(document, query("jwt_vc_json", listOf("A"))).isErr)
        }

    @Test
    fun shouldRefuseAFormatWithoutATypeConstraintHere() =
        runTest {
            val mdoc =
                DcqlCredentialQuery(id = "q", format = "mso_mdoc", meta = buildJsonObject { put("doctype_value", "org.iso.18013.5.1.mDL") })

            assertTrue(matches(credential(listOf("A")), mdoc).isErr)
        }

    @Test
    fun shouldAcceptAnSdJwtVcWhoseVctIsListedWithoutAnyMetadataLookup() =
        runTest {
            val metadata = CountingTypeMetadataCommand()
            val matcher = testCredentialTypeMatcher(metadata)

            val result = matcher.matches(buildJsonObject { put("vct", "https://example.org/pid") }, sdJwtQuery("https://example.org/pid"))

            assertTrue(result.accepted())
            assertTrue(metadata.resolvedVcts.isEmpty())
        }

    @Test
    fun shouldAcceptAnSdJwtVcThatExtendsAListedType() =
        runTest {
            val metadata =
                CountingTypeMetadataCommand(
                    StaticTypeMetadataResolver(
                        mapOf(
                            "https://example.org/child" to SdJwtVcTypeMetadata(vct = "https://example.org/child", extends = "https://example.org/pid"),
                            "https://example.org/pid" to SdJwtVcTypeMetadata(vct = "https://example.org/pid"),
                        ),
                    ),
                )

            val result =
                testCredentialTypeMatcher(metadata)
                    .matches(buildJsonObject { put("vct", "https://example.org/child") }, sdJwtQuery("https://example.org/pid"))

            assertTrue(result.accepted())
            assertEquals(listOf("https://example.org/child", "https://example.org/pid"), metadata.resolvedVcts)
        }

    @Test
    fun shouldRefuseAnSdJwtVcOfAnUnlistedTypeWithNoParent() =
        runTest {
            val metadata =
                CountingTypeMetadataCommand(
                    StaticTypeMetadataResolver(mapOf("https://example.org/other" to SdJwtVcTypeMetadata(vct = "https://example.org/other"))),
                )

            val result =
                testCredentialTypeMatcher(metadata)
                    .matches(buildJsonObject { put("vct", "https://example.org/other") }, sdJwtQuery("https://example.org/pid"))

            assertFalse(result.accepted())
        }

    @Test
    fun shouldFailAnSdJwtVcWithoutAVct() =
        runTest {
            assertTrue(testCredentialTypeMatcher().matches(buildJsonObject { }, sdJwtQuery("https://example.org/pid")).isErr)
        }

    @Test
    fun shouldFailAnSdJwtVcWhoseVctIsNotAString() =
        runTest {
            assertTrue(testCredentialTypeMatcher().matches(buildJsonObject { put("vct", 1) }, sdJwtQuery("https://example.org/pid")).isErr)
        }

    @Test
    fun shouldFailAnSdJwtVcWhoseIntegrityClaimIsNotAString() =
        runTest {
            val document = buildJsonObject { put("vct", "https://example.org/other"); put("vct#integrity", 1) }

            assertTrue(testCredentialTypeMatcher().matches(document, sdJwtQuery("https://example.org/pid")).isErr)
        }

    @Test
    fun shouldFailAnSdJwtVcWhoseTypeMetadataCannotBeFetched() =
        runTest {
            val result =
                testCredentialTypeMatcher().matches(buildJsonObject { put("vct", "https://example.org/other") }, sdJwtQuery("https://example.org/pid"))

            assertTrue(result.isErr)
        }
}
