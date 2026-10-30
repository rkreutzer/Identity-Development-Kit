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

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpStatusCode
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs

class UrlTypeMetadataResolverTest {
    private val vct = "https://example.org/pid"

    private fun resolver(
        status: HttpStatusCode = HttpStatusCode.OK,
        body: ByteArray,
    ) = UrlTypeMetadataResolver(HttpClient(MockEngine { respond(content = body, status = status) }))

    @Test
    fun shouldRetainTheResponseOctetsIncludingWhitespaceAndUnknownFields() =
        runTest {
            val body = "{\n  \"vct\" : \"https://example.org/pid\",\n  \"future\": [1, 2]\n}\n".encodeToByteArray()

            val success = assertIs<TypeMetadataResolutionResult.Success>(resolver(body = body).resolve(vct))

            assertEquals(vct, success.metadata.vct)
            assertContentEquals(body, success.rawDocument)
        }

    @Test
    fun shouldRetainNonAsciiOctetsUnchanged() =
        runTest {
            val body = """{"vct":"https://example.org/pid","name":"Pässe"}""".encodeToByteArray()

            val success = assertIs<TypeMetadataResolutionResult.Success>(resolver(body = body).resolve(vct))

            assertContentEquals(body, success.rawDocument)
        }

    @Test
    fun shouldFailOnMalformedJsonWithoutReturningAnyDocument() =
        runTest {
            val result = resolver(body = "{not json".encodeToByteArray()).resolve(vct)

            val failure = assertIs<TypeMetadataResolutionResult.Failure>(result)
            assertIs<TypeMetadataResolutionError.NetworkError>(failure.error)
        }

    @Test
    fun shouldFailOnAnEmptyBody() =
        runTest {
            val failure = assertIs<TypeMetadataResolutionResult.Failure>(resolver(body = ByteArray(0)).resolve(vct))

            assertIs<TypeMetadataResolutionError.InvalidFormat>(failure.error)
        }

    @Test
    fun shouldReportNotFoundFor404() =
        runTest {
            val failure =
                assertIs<TypeMetadataResolutionResult.Failure>(resolver(HttpStatusCode.NotFound, ByteArray(0)).resolve(vct))

            assertEquals(TypeMetadataResolutionError.NotFound, failure.error)
        }

    @Test
    fun shouldReportANetworkErrorForOtherHttpFailures() =
        runTest {
            val failure =
                assertIs<TypeMetadataResolutionResult.Failure>(resolver(HttpStatusCode.InternalServerError, ByteArray(0)).resolve(vct))

            assertIs<TypeMetadataResolutionError.NetworkError>(failure.error)
        }

    @Test
    fun shouldRefuseAVctThatIsNotHttps() =
        runTest {
            val failure =
                assertIs<TypeMetadataResolutionResult.Failure>(resolver(body = ByteArray(0)).resolve("urn:example:pid"))

            assertEquals(TypeMetadataResolutionError.UnsupportedVct("urn:example:pid"), failure.error)
        }
}
