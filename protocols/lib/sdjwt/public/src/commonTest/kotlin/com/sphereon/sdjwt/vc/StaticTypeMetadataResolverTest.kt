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

import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull

class StaticTypeMetadataResolverTest {
    private val metadata = SdJwtVcTypeMetadata(vct = "https://example.org/pid", name = "PID")
    private val document = """{ "vct" : "https://example.org/pid", "name":"PID", "unknown": 1 }""".encodeToByteArray()

    @Test
    fun shouldResolveMetadataWithoutRawDocumentWhenNoneWasSupplied() =
        runTest {
            val result = StaticTypeMetadataResolver(mapOf(metadata.vct to metadata)).resolve(metadata.vct)

            val success = assertIs<TypeMetadataResolutionResult.Success>(result)
            assertEquals(metadata, success.metadata)
            assertNull(success.rawDocument)
        }

    @Test
    fun shouldReturnTheSuppliedRawDocumentByteForByte() =
        runTest {
            val resolver = StaticTypeMetadataResolver(mapOf(metadata.vct to metadata), mapOf(metadata.vct to document))

            val success = assertIs<TypeMetadataResolutionResult.Success>(resolver.resolve(metadata.vct))

            assertContentEquals(document, success.rawDocument)
        }

    @Test
    fun shouldNotLetACallerMutateTheRetainedRawDocument() =
        runTest {
            val resolver = StaticTypeMetadataResolver(mapOf(metadata.vct to metadata), mapOf(metadata.vct to document.copyOf()))
            val first = assertIs<TypeMetadataResolutionResult.Success>(resolver.resolve(metadata.vct))

            requireNotNull(first.rawDocument)[0] = 0
            val second = assertIs<TypeMetadataResolutionResult.Success>(resolver.resolve(metadata.vct))

            assertContentEquals(document, second.rawDocument)
        }

    @Test
    fun shouldRefuseARawDocumentThatDecodesToOtherMetadata() {
        val other = """{"vct":"https://example.org/pid","name":"Other"}""".encodeToByteArray()

        assertFailsWith<IllegalArgumentException> {
            StaticTypeMetadataResolver(mapOf(metadata.vct to metadata), mapOf(metadata.vct to other))
        }
    }

    @Test
    fun shouldRefuseARawDocumentForAnUnregisteredVct() {
        assertFailsWith<IllegalArgumentException> {
            StaticTypeMetadataResolver(emptyMap(), mapOf(metadata.vct to document))
        }
    }

    @Test
    fun shouldReportNotFoundForAnUnregisteredVct() =
        runTest {
            val result = StaticTypeMetadataResolver(emptyMap()).resolve("https://example.org/unknown")

            val failure = assertIs<TypeMetadataResolutionResult.Failure>(result)
            assertEquals(TypeMetadataResolutionError.NotFound, failure.error)
        }
}
