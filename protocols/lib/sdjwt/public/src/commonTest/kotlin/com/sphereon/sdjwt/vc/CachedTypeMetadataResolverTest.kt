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
import kotlin.test.assertIs
import kotlin.test.assertNull

class CachedTypeMetadataResolverTest {
    private class CountingResolver(
        private val result: TypeMetadataResolutionResult,
    ) : TypeMetadataResolver {
        var calls = 0

        override suspend fun resolve(vct: String): TypeMetadataResolutionResult {
            calls++
            return result
        }

        override fun supports(vct: String): Boolean = true
    }

    private val vct = "https://example.org/pid"
    private val document = """{"vct":"https://example.org/pid"}""".encodeToByteArray()
    private val metadata = SdJwtVcTypeMetadata(vct = vct)

    @Test
    fun shouldServeACachedHitWithTheOriginalDocument() =
        runTest {
            val delegate = CountingResolver(TypeMetadataResolutionResult.Success(metadata, document))
            val cached = CachedTypeMetadataResolver(delegate)

            cached.resolve(vct)
            val hit = assertIs<TypeMetadataResolutionResult.Success>(cached.resolve(vct))

            assertEquals(1, delegate.calls)
            assertContentEquals(document, hit.rawDocument)
        }

    @Test
    fun shouldKeepAMissingRepresentationMissingOnACacheHit() =
        runTest {
            val delegate = CountingResolver(TypeMetadataResolutionResult.Success(metadata))
            val cached = CachedTypeMetadataResolver(delegate)

            cached.resolve(vct)
            val hit = assertIs<TypeMetadataResolutionResult.Success>(cached.resolve(vct))

            assertNull(hit.rawDocument)
        }

    @Test
    fun shouldNotCacheAFailure() =
        runTest {
            val delegate = CountingResolver(TypeMetadataResolutionResult.Failure(TypeMetadataResolutionError.NotFound))
            val cached = CachedTypeMetadataResolver(delegate)

            cached.resolve(vct)
            val second = cached.resolve(vct)

            assertEquals(2, delegate.calls)
            assertIs<TypeMetadataResolutionResult.Failure>(second)
        }

    @Test
    fun shouldNotLetACallerMutateTheCachedDocument() =
        runTest {
            val cached = CachedTypeMetadataResolver(CountingResolver(TypeMetadataResolutionResult.Success(metadata, document.copyOf())))
            val first = assertIs<TypeMetadataResolutionResult.Success>(cached.resolve(vct))

            requireNotNull(first.rawDocument)[0] = 0
            val second = assertIs<TypeMetadataResolutionResult.Success>(cached.resolve(vct))

            assertContentEquals(document, second.rawDocument)
        }

    @Test
    fun shouldRefetchAfterEviction() =
        runTest {
            val delegate = CountingResolver(TypeMetadataResolutionResult.Success(metadata, document))
            val cached = CachedTypeMetadataResolver(delegate)

            cached.resolve(vct)
            cached.evict(vct)
            cached.resolve(vct)

            assertEquals(2, delegate.calls)
        }
}
