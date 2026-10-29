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

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.binary.TypeToken
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.encodeToBase64
import com.sphereon.core.api.error.IdkError
import com.sphereon.crypto.core.generic.DigestAlg
import com.sphereon.crypto.core.generic.hash
import com.sphereon.sdjwt.vc.command.ResolveTypeMetadataCommand
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

class SdJwtVcTypeMatcherImplTest {
    private class MetadataCommand(
        private val resolver: TypeMetadataResolver,
        private val outerFailure: IdkError? = null,
    ) : ResolveTypeMetadataCommand {
        val resolved = mutableListOf<String>()

        override val commandId: String = ResolveTypeMetadataCommand.COMMAND_ID
        override val inputTypeToken: TypeToken<ResolveTypeMetadataArgs> = typeToken<ResolveTypeMetadataArgs>()
        override val outputTypeToken: TypeToken<TypeMetadataResolutionResult> = typeToken<TypeMetadataResolutionResult>()
        override val isEnabled: Boolean = true

        override suspend fun supports(args: Any): Boolean = args is ResolveTypeMetadataArgs

        override suspend fun execute(args: ResolveTypeMetadataArgs): IdkResult<TypeMetadataResolutionResult, IdkError> {
            resolved += args.vct
            return outerFailure?.let { com.sphereon.core.api.Err(it) } ?: Ok(resolver.resolve(args.vct))
        }
    }

    private val leaf = "https://example.org/leaf"
    private val middle = "https://example.org/middle"
    private val root = "https://example.org/root"
    private val other = "https://example.org/other"

    private fun document(
        vct: String,
        extends: String? = null,
        extendsIntegrity: String? = null,
    ): ByteArray =
        buildString {
            append("""{"vct":"$vct"""")
            extends?.let { append(""","extends":"$it"""") }
            extendsIntegrity?.let { append(""","extends#integrity":"$it"""") }
            append("}")
        }.encodeToByteArray()

    private fun sri(document: ByteArray) = "sha256-" + hash(document, DigestAlg.SHA256).encodeToBase64()

    private fun metadataOf(document: ByteArray) =
        kotlinx.serialization.json.Json { ignoreUnknownKeys = true }.decodeFromString<SdJwtVcTypeMetadata>(document.decodeToString())

    private fun matcher(
        documents: Map<String, ByteArray>,
        outerFailure: IdkError? = null,
    ): Pair<SdJwtVcTypeMatcherImpl, MetadataCommand> {
        val resolver = StaticTypeMetadataResolver(documents.mapValues { metadataOf(it.value) }, documents)
        val command = MetadataCommand(resolver, outerFailure)
        return SdJwtVcTypeMatcherImpl(command) to command
    }

    private suspend fun SdJwtVcTypeMatcherImpl.assertAccepted(
        vct: String,
        accepted: List<String>,
        integrity: String? = null,
    ) = assertTrue(assertIsOk(matches(vct, accepted, integrity)))

    private fun assertIsOk(result: IdkResult<Boolean, IdkError>): Boolean {
        assertTrue(result.isOk, "expected Ok but was ${result.errorOrNull()?.message?.defaultMessage}")
        return result.getOrNull() == true
    }

    @Test
    fun shouldAcceptAnExactVctWithoutResolvingAnyMetadata() =
        runTest {
            val (matcher, command) = matcher(emptyMap())

            matcher.assertAccepted(leaf, listOf(other, leaf))

            assertTrue(command.resolved.isEmpty())
        }

    @Test
    fun shouldRefuseAnUnlistedVctWhoseChainContainsNothingListed() =
        runTest {
            val (matcher, _) = matcher(mapOf(leaf to document(leaf, middle), middle to document(middle)))

            val result = matcher.matches(leaf, listOf(root), null)

            assertFalse(assertIsOk(result))
        }

    @Test
    fun shouldAcceptADirectParent() =
        runTest {
            val (matcher, command) = matcher(mapOf(leaf to document(leaf, root), root to document(root)))

            matcher.assertAccepted(leaf, listOf(root))

            assertEquals(listOf(leaf, root), command.resolved)
        }

    @Test
    fun shouldAcceptAnAncestorThroughAParent() =
        runTest {
            val (matcher, _) = matcher(mapOf(leaf to document(leaf, middle), middle to document(middle, root), root to document(root)))

            matcher.assertAccepted(leaf, listOf(root))
        }

    @Test
    fun shouldAcceptAnAncestorAtAnyDepthOfALongChain() =
        runTest {
            val names = (0..40).map { "https://example.org/t$it" }
            val documents = names.mapIndexed { index, name -> name to document(name, names.getOrNull(index + 1)) }.toMap()
            val (matcher, _) = matcher(documents)

            matcher.assertAccepted(names.first(), listOf(names.last()))
        }

    @Test
    fun shouldAcceptWhenAnyOfSeveralAcceptedTypesIsAnAncestor() =
        runTest {
            val (matcher, _) = matcher(mapOf(leaf to document(leaf, root), root to document(root)))

            matcher.assertAccepted(leaf, listOf(other, root))
        }

    @Test
    fun shouldRejectASelfReferencingChain() =
        runTest {
            val (matcher, _) = matcher(mapOf(leaf to document(leaf, leaf)))

            assertTrue(matcher.matches(leaf, listOf(root), null).isErr)
        }

    @Test
    fun shouldRejectAMultiNodeLoop() =
        runTest {
            val (matcher, _) = matcher(mapOf(leaf to document(leaf, middle), middle to document(middle, root), root to document(root, leaf)))

            assertTrue(matcher.matches(leaf, listOf(other), null).isErr)
        }

    @Test
    fun shouldRejectALoopBehindAMatchingAncestor() =
        runTest {
            val (matcher, _) = matcher(mapOf(leaf to document(leaf, middle), middle to document(middle, root), root to document(root, middle)))

            assertTrue(matcher.matches(leaf, listOf(middle), null).isErr)
        }

    @Test
    fun shouldRejectAnUnavailableParentBehindAMatchingAncestor() =
        runTest {
            val (matcher, _) = matcher(mapOf(leaf to document(leaf, middle), middle to document(middle, root)))

            assertTrue(matcher.matches(leaf, listOf(middle), null).isErr)
        }

    @Test
    fun shouldRejectADocumentThatNamesAnotherVctThanTheOneResolved() =
        runTest {
            val resolver = StaticTypeMetadataResolver(mapOf(leaf to SdJwtVcTypeMetadata(vct = other, extends = root), root to SdJwtVcTypeMetadata(vct = root)))

            assertTrue(SdJwtVcTypeMatcherImpl(MetadataCommand(resolver)).matches(leaf, listOf(root), null).isErr)
        }

    @Test
    fun shouldRejectAParentDocumentThatNamesAnotherVct() =
        runTest {
            val resolver =
                StaticTypeMetadataResolver(
                    mapOf(
                        leaf to SdJwtVcTypeMetadata(vct = leaf, extends = middle),
                        middle to SdJwtVcTypeMetadata(vct = other, extends = root),
                        root to SdJwtVcTypeMetadata(vct = root),
                    ),
                )

            assertTrue(SdJwtVcTypeMatcherImpl(MetadataCommand(resolver)).matches(leaf, listOf(root), null).isErr)
        }

    @Test
    fun shouldNotFollowExtendsOfAMismatchedDocument() =
        runTest {
            val resolver = StaticTypeMetadataResolver(mapOf(leaf to SdJwtVcTypeMetadata(vct = other, extends = root)))
            val command = MetadataCommand(resolver)

            SdJwtVcTypeMatcherImpl(command).matches(leaf, listOf(root), null)

            assertEquals(listOf(leaf), command.resolved)
        }

    @Test
    fun shouldAcceptMatchingIntegrityPinsOnTheRootAndOnTheParent() =
        runTest {
            val rootDocument = document(root)
            val leafDocument = document(leaf, root, sri(rootDocument))
            val (matcher, _) = matcher(mapOf(leaf to leafDocument, root to rootDocument))

            matcher.assertAccepted(leaf, listOf(root), sri(leafDocument))
        }

    @Test
    fun shouldRejectAWrongIntegrityPinOnTheRoot() =
        runTest {
            val (matcher, _) = matcher(mapOf(leaf to document(leaf, root), root to document(root)))

            assertTrue(matcher.matches(leaf, listOf(root), sri("tampered".encodeToByteArray())).isErr)
        }

    @Test
    fun shouldRejectAWrongIntegrityPinOnTheParent() =
        runTest {
            val leafDocument = document(leaf, root, sri("tampered".encodeToByteArray()))
            val (matcher, _) = matcher(mapOf(leaf to leafDocument, root to document(root)))

            assertTrue(matcher.matches(leaf, listOf(root), null).isErr)
        }

    @Test
    fun shouldRejectAWrongParentPinBehindAMatchingAncestor() =
        runTest {
            val middleDocument = document(middle, root, sri("tampered".encodeToByteArray()))
            val leafDocument = document(leaf, middle, sri(middleDocument))
            val (matcher, _) = matcher(mapOf(leaf to leafDocument, middle to middleDocument, root to document(root)))

            assertTrue(matcher.matches(leaf, listOf(middle), null).isErr)
        }

    @Test
    fun shouldRejectAPinWhenNoOriginalDocumentIsAvailable() =
        runTest {
            val resolver = StaticTypeMetadataResolver(mapOf(leaf to SdJwtVcTypeMetadata(vct = leaf, extends = root), root to SdJwtVcTypeMetadata(vct = root)))

            assertTrue(SdJwtVcTypeMatcherImpl(MetadataCommand(resolver)).matches(leaf, listOf(root), sri(document(leaf, root))).isErr)
        }

    @Test
    fun shouldRejectAMalformedPin() =
        runTest {
            val (matcher, _) = matcher(mapOf(leaf to document(leaf, root), root to document(root)))

            assertTrue(matcher.matches(leaf, listOf(root), "not-an-expression").isErr)
        }

    @Test
    fun shouldReevaluateTheCurrentPinAgainstCachedBytes() =
        runTest {
            val leafDocument = document(leaf, root)
            val rootDocument = document(root)
            val resolver = StaticTypeMetadataResolver(mapOf(leaf to metadataOf(leafDocument), root to metadataOf(rootDocument)), mapOf(leaf to leafDocument, root to rootDocument))
            val matcher = SdJwtVcTypeMatcherImpl(MetadataCommand(CachedTypeMetadataResolver(resolver)))

            assertTrue(assertIsOk(matcher.matches(leaf, listOf(root), sri(leafDocument))))
            assertTrue(matcher.matches(leaf, listOf(root), sri("tampered".encodeToByteArray())).isErr)
        }

    @Test
    fun shouldReportANotFoundParent() =
        runTest {
            val (matcher, _) = matcher(mapOf(leaf to document(leaf, root)))

            assertTrue(matcher.matches(leaf, listOf(other), null).isErr)
        }

    private suspend fun failureOf(error: TypeMetadataResolutionError): IdkError {
        val command =
            MetadataCommand(
                object : TypeMetadataResolver {
                    override suspend fun resolve(vct: String) = TypeMetadataResolutionResult.Failure(error)

                    override fun supports(vct: String) = true
                },
            )
        return assertIs<IdkError>(SdJwtVcTypeMatcherImpl(command).matches(leaf, listOf(root), null).errorOrNull())
    }

    @Test
    fun shouldKeepTheCauseOfANetworkFailure() =
        runTest {
            val cause = IllegalStateException("connection reset")

            val error = failureOf(TypeMetadataResolutionError.NetworkError("down", cause))

            assertEquals(cause, error.exception)
        }

    @Test
    fun shouldRefuseOnInvalidFormatNotFoundUnsupportedAndCircularFailures() =
        runTest {
            failureOf(TypeMetadataResolutionError.InvalidFormat("bad"))
            failureOf(TypeMetadataResolutionError.NotFound)
            failureOf(TypeMetadataResolutionError.UnsupportedVct(leaf))
            failureOf(TypeMetadataResolutionError.CircularDependency(leaf, listOf(leaf, leaf)))
        }

    @Test
    fun shouldPropagateAnOuterCommandFailure() =
        runTest {
            val outer = IdkError.UNKNOWN_ERROR(message = "command failed")
            val (matcher, _) = matcher(emptyMap(), outer)

            assertEquals(outer, matcher.matches(leaf, listOf(root), null).errorOrNull())
        }

    @Test
    fun shouldRejectABlankVct() =
        runTest {
            val (matcher, _) = matcher(emptyMap())

            assertTrue(matcher.matches(" ", listOf(root), null).isErr)
        }

    @Test
    fun shouldRejectAnEmptyAcceptedList() =
        runTest {
            val (matcher, _) = matcher(emptyMap())

            assertTrue(matcher.matches(leaf, emptyList(), null).isErr)
        }
}
