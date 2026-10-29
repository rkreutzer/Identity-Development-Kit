/*
 * © 2026 Sphereon International B.V.
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

package com.sphereon.openid.oid4vci.issuer.impl.command

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.error.IdkError
import com.sphereon.openid.oid4vci.issuer.spi.IssuerFederationEntityResolver
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class IssuerFederationEntitySupportTest {
    private val credentialIssuer = "https://summa.fed.nk.sphereon.com/oid4vci/summa"

    private fun resolver(answer: suspend (String) -> IdkResult<String?, IdkError>) =
        object : IssuerFederationEntityResolver {
            override suspend fun resolveFederationEntityIdentifier(credentialIssuer: String) = answer(credentialIssuer)
        }

    @Test
    fun noBoundResolverMeansNoFederationEntity() =
        runTest {
            val result = resolveIssuerFederationEntityIdentifier(null, credentialIssuer)

            assertTrue(result.isOk)
            assertNull(result.value)
        }

    @Test
    fun aFederationEntityIsNamedByItsCredentialIssuer() =
        runTest {
            var asked: String? = null
            val result =
                resolveIssuerFederationEntityIdentifier(
                    resolver {
                        asked = it
                        Ok(it)
                    },
                    credentialIssuer,
                )

            assertEquals(credentialIssuer, asked)
            assertEquals(credentialIssuer, result.value)
        }

    @Test
    fun anIssuerThatIsNotAFederationEntityGetsNoIdentifier() =
        runTest {
            val result = resolveIssuerFederationEntityIdentifier(resolver { Ok(null) }, credentialIssuer)

            assertTrue(result.isOk)
            assertNull(result.value)
        }

    @Test
    fun anIdentifierOtherThanTheCredentialIssuerIsRefused() =
        runTest {
            val result =
                resolveIssuerFederationEntityIdentifier(resolver { Ok("https://other.example.com") }, credentialIssuer)

            assertTrue(result.isErr)
            assertEquals("issuer_federation_entity_mismatch", result.error.code)
        }

    @Test
    fun aResolverFailureRefusesTheIssuance() =
        runTest {
            val failure = IdkError.SERVICE_UNAVAILABLE_ERROR(message = "platform unreachable")
            val reported = resolveIssuerFederationEntityIdentifier(resolver { Err(failure) }, credentialIssuer)
            val thrown = resolveIssuerFederationEntityIdentifier(resolver { error("boom") }, credentialIssuer)

            assertTrue(reported.isErr)
            assertEquals(failure.code, reported.error.code)
            assertTrue(thrown.isErr)
            assertEquals("SERVICE_UNAVAILABLE", thrown.error.code)
        }
}
