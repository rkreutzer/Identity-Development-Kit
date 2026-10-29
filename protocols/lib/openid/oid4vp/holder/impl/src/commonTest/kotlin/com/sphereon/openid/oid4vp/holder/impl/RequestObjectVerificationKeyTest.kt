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

package com.sphereon.openid.oid4vp.holder.impl

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.asErrorResult
import com.sphereon.core.api.encodeToBase64Url
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.error.IdkErrorType
import com.sphereon.crypto.jose.jws.JwsJsonFlattened
import com.sphereon.crypto.jose.jws.JwsJsonGeneral
import com.sphereon.crypto.jose.jws.JwsValidationResult
import com.sphereon.crypto.jose.jws.JwtCompactResult
import com.sphereon.crypto.jose.jws.JwtService
import com.sphereon.crypto.jose.jws.PreparedJwsObject
import com.sphereon.crypto.jose.jws.command.CreateJwsArgs
import com.sphereon.crypto.jose.jws.command.CreateJwsJsonArgs
import com.sphereon.crypto.jose.jws.command.VerifyJwsArgs
import com.sphereon.crypto.resolution.IIdentifierMethod
import com.sphereon.crypto.resolution.extern.ExternalIdentifierOpts
import com.sphereon.crypto.resolution.extern.ExternalIdentifierOptsOrResult
import com.sphereon.crypto.resolution.extern.ExternalIdentifierResult
import com.sphereon.crypto.resolution.extern.MultiExternalIdentifierService
import com.sphereon.ktor.http.client.FetchRequestUriCommandImpl
import com.sphereon.ktor.http.client.ParseUriQueryCommandImpl
import com.sphereon.ktor.http.client.provider.HttpClientEngineType
import com.sphereon.ktor.http.client.provider.HttpClientFactory
import com.sphereon.ktor.http.client.provider.HttpClientOptions
import com.sphereon.oauth2.client.JarService
import com.sphereon.oauth2.client.command.CreateEncryptedJarArgs
import com.sphereon.oauth2.client.command.CreateSignedJarArgs
import com.sphereon.oauth2.client.command.MergeRequestObjectArgs
import com.sphereon.oauth2.client.command.ParseJarArgs
import com.sphereon.openid.oid4vp.common.impl.UnavailableOid4vpRequestTrustMaterialProvider
import io.ktor.client.HttpClient
import io.ktor.http.encodeURLParameter
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * A Request Object must be verified with the key its own client identity designates. When the
 * outer `client_id` is omitted, the key must not fall back to request-supplied `client_metadata`,
 * otherwise any key can sign a Request Object that claims a trusted X.509 or DID client identifier.
 */
class RequestObjectVerificationKeyTest {
    @Test
    fun requestObjectWithoutRequiredTypIsRejectedBeforeVerificationKeySelection() =
        runTest {
            assertRequestObjectTypRejected(header = buildJsonObject { put("alg", "ES256") })
        }

    @Test
    fun requestObjectWithWrongTypIsRejectedBeforeVerificationKeySelection() =
        runTest {
            assertRequestObjectTypRejected(
                header = buildJsonObject {
                    put("alg", "ES256")
                    put("typ", "jwt")
                },
            )
        }

    @Test
    fun requestObjectWithNonStringTypIsRejectedBeforeVerificationKeySelection() =
        runTest {
            assertRequestObjectTypRejected(
                header = buildJsonObject {
                    put("alg", "ES256")
                    put("typ", 42)
                },
            )
        }

    @Test
    fun requestObjectClaimingAnX509ClientIdIsNeverVerifiedWithAClientMetadataKey() =
        runTest {
            val jarService = RecordingJarService()
            val requestObject =
                compactJws(
                    header =
                        buildJsonObject {
                            put("alg", "ES256")
                            put("typ", "oauth-authz-req+jwt")
                            putJsonArray("x5c") { add(TRUSTED_VERIFIER_LEAF_CERTIFICATE) }
                        },
                    payload = authorizationRequestClaims(clientId = "x509_san_dns:verifier.example"),
                )

            val result =
                parseCommand(jarService).parseAuthorizationRequest(
                    requestUri = "openid4vp://?request=$requestObject&client_metadata=${attackerClientMetadata(kid = null).encodeURLParameter()}",
                    walletConfig = null,
                )

            assertTrue(result.isErr, "an X.509 client identity must be verified against governed X.509 trust material")
            assertEquals("X5C_TRUST_MATERIAL_UNAVAILABLE", result.error.code)
            assertEquals(0, jarService.mergeCalls, "the request-supplied client_metadata key must never verify the Request Object")
        }

    @Test
    fun requestObjectClaimingADidClientIdIsNeverVerifiedWithAClientMetadataKey() =
        runTest {
            val jarService = RecordingJarService()
            val kid = "did:example:verifier#key-1"
            val requestObject =
                compactJws(
                    header =
                        buildJsonObject {
                            put("alg", "ES256")
                            put("typ", "oauth-authz-req+jwt")
                            put("kid", kid)
                        },
                    payload = authorizationRequestClaims(clientId = "decentralized_identifier:did:example:verifier"),
                )

            val result =
                parseCommand(jarService).parseAuthorizationRequest(
                    requestUri = "openid4vp://?request=$requestObject&client_metadata=${attackerClientMetadata(kid = kid).encodeURLParameter()}",
                    walletConfig = null,
                )

            assertTrue(result.isErr, "a DID client identity must be verified with a verification method of that DID")
            assertEquals("DID_KID_RESOLUTION_FAILED", result.error.code)
            assertEquals(0, jarService.mergeCalls, "the request-supplied client_metadata key must never verify the Request Object")
        }

    private fun parseCommand(jarService: JarService): ParseAuthorizationRequestCommandImpl {
        val execution = TestExecutionContext.createExecution()
        return ParseAuthorizationRequestCommandImpl(
            execution = execution,
            parseUriQueryCommand = ParseUriQueryCommandImpl(execution),
            fetchRequestUriCommand = FetchRequestUriCommandImpl(execution, NoNetworkHttpClientFactory),
            jarService = jarService,
            httpClientFactory = NoNetworkHttpClientFactory,
            externalIdentifierService = UnresolvableIdentifierService,
            jwtService = UnusedJwtService,
            requestTrustMaterialProvider = UnavailableOid4vpRequestTrustMaterialProvider(),
        )
    }

    private suspend fun assertRequestObjectTypRejected(header: JsonObject) {
        val jarService = RecordingJarService()
        val requestObject = compactJws(header = header, payload = authorizationRequestClaims(clientId = "verifier.example"))
        val result =
            parseCommand(jarService).parseAuthorizationRequest(
                requestUri = "openid4vp://?request=$requestObject",
                walletConfig = null,
            )

        assertTrue(result.isErr, "a Request Object without the required typ must be rejected before processing")
        assertEquals(0, jarService.mergeCalls, "a Request Object with an invalid typ must not be merged or processed")
    }

    private fun authorizationRequestClaims(clientId: String): JsonObject =
        buildJsonObject {
            put("client_id", clientId)
            put("response_type", "vp_token")
            put("response_mode", "direct_post")
            put("response_uri", "https://attacker.example/response")
            put("nonce", "nonce-12345678")
            put("state", "state-12345678")
        }

    private fun attackerClientMetadata(kid: String?): String =
        buildJsonObject {
            putJsonObject("jwks") {
                putJsonArray("keys") {
                    add(
                        buildJsonObject {
                            put("kty", "EC")
                            put("crv", "P-256")
                            put("x", "xZNrNXMbdI_Uj7ImFaMWBGHkli_c6GIfrlPneg62TLU")
                            put("y", "MXpChijPuGECrWs2YlfmRxe8C92Ag7cpInPfXW2jkjU")
                            kid?.let { put("kid", it) }
                        },
                    )
                }
            }
        }.toString()

    private fun compactJws(
        header: JsonObject,
        payload: JsonObject,
    ): String =
        listOf(header.toString(), payload.toString(), "not-a-signature")
            .joinToString(".") { it.encodeToByteArray().encodeToBase64Url().trimEnd('=') }

    private class RecordingJarService : JarService {
        var mergeCalls = 0

        override suspend fun createSignedJar(args: CreateSignedJarArgs) = Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "not used"))

        override suspend fun createEncryptedJar(args: CreateEncryptedJarArgs) = Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "not used"))

        override suspend fun parseJar(args: ParseJarArgs) = Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "not used"))

        override suspend fun mergeRequestObject(args: MergeRequestObjectArgs) =
            Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "request object verified with ${args.verificationKey}")).also { mergeCalls++ }

        override val commands: JarService.Commands
            get() = error("JAR commands are not used by request object key selection")
    }

    private object NoNetworkHttpClientFactory : HttpClientFactory {
        override fun createClient(options: HttpClientOptions): HttpClient = error("request object key selection must not open an HTTP client")

        override fun isSupportedOptions(options: HttpClientOptions) = true

        override fun getEngineTypesSupported() = listOf(HttpClientEngineType.CIO)

        override fun getEngineTypeDefault() = HttpClientEngineType.CIO
    }

    private object UnresolvableIdentifierService : MultiExternalIdentifierService {
        override val supportedIdentifierMethods: List<IIdentifierMethod> = emptyList()

        override suspend fun isSupportedIdentifier(identifier: Any): Boolean = false

        override suspend fun isSupportedIdentifierMethod(identifierMethod: IIdentifierMethod): Boolean = false

        override suspend fun isSupportedOpts(opts: ExternalIdentifierOptsOrResult): Boolean = false

        override suspend fun asSupportedOpts(opts: ExternalIdentifierOptsOrResult): IdkResult<ExternalIdentifierOpts, IdkErrorType> =
            IdkError.COMMAND_ARG_NOT_SUPPORTED_ERROR(message = "identifier resolution is unavailable in this test").asErrorResult()

        override suspend fun resolve(opts: ExternalIdentifierOptsOrResult): IdkResult<ExternalIdentifierResult, IdkErrorType> =
            IdkError.COMMAND_ARG_NOT_SUPPORTED_ERROR(message = "identifier resolution is unavailable in this test").asErrorResult()
    }

    private object UnusedJwtService : JwtService {
        override val commands: JwtService.Commands
            get() = error("JWS commands are not used by request object key selection")

        override fun assembleJwsGeneral(
            prepared: PreparedJwsObject,
            signatureBytes: ByteArray,
        ): JwsJsonGeneral = error("JWS creation is not used by request object key selection")

        override fun assembleJwsFlattened(
            prepared: PreparedJwsObject,
            signatureBytes: ByteArray,
        ): JwsJsonFlattened = error("JWS creation is not used by request object key selection")

        override fun assembleJwsCompact(
            prepared: PreparedJwsObject,
            signatureBytes: ByteArray,
        ): JwtCompactResult = error("JWS creation is not used by request object key selection")

        override suspend fun prepareJws(args: CreateJwsJsonArgs): IdkResult<PreparedJwsObject, IdkError> =
            error("JWS creation is not used by request object key selection")

        override suspend fun createJwsCompact(args: CreateJwsArgs): IdkResult<JwtCompactResult, IdkError> =
            error("JWS creation is not used by request object key selection")

        override suspend fun createJwsJsonFlattened(args: CreateJwsJsonArgs): IdkResult<JwsJsonFlattened, IdkError> =
            error("JWS creation is not used by request object key selection")

        override suspend fun createJwsJsonGeneral(args: CreateJwsJsonArgs): IdkResult<JwsJsonGeneral, IdkError> =
            error("JWS creation is not used by request object key selection")

        override suspend fun verifyJws(args: VerifyJwsArgs): IdkResult<JwsValidationResult, IdkError> =
            error("JWS verification is not reached before the verification key is selected")
    }

    private companion object {
        const val TRUSTED_VERIFIER_LEAF_CERTIFICATE =
            "MIIBtDCCAVqgAwIBAgICB9IwCgYIKoZIzj0EAwIwKjEoMCYGA1UEAwwfUmVxdWVzdCBPYmplY3QgVGVzdCBWZXJpZmllciBDQTAgFw0y" +
                "NTAxMDEwMDAwMDBaGA8yMTI1MDEwMTAwMDAwMFowGzEZMBcGA1UEAwwQdmVyaWZpZXIuZXhhbXBsZTBZMBMGByqGSM49AgEGCCqGSM49" +
                "AwEHA0IABIOu1xW/33w8OBveSt5zU4N5aroFQcc10HdrYdwFCfXElzUUBVZ5QZBBuoSRTivhMhw5SDdDGAywm8OLk4vJTiujfTB7MAwG" +
                "A1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBsGA1UdEQQUMBKCEHZlcmlmaWVyLmV4YW1wbGUwHQYDVR0OBBYEFM4LEXNHEHHEbLJx" +
                "G5w1Et8OgOHzMB8GA1UdIwQYMBaAFBv6tuZiDqz23peqoGHc25H5edRbMAoGCCqGSM49BAMCA0gAMEUCIQCk+YCurB1D2dRqCe5Eeedc" +
                "XT3fDdDql4iF2VSJNtx0hQIgPARTjfL3c571Axx1rLCTpyPn3mlOEtDIT3SZx3POMvs="
    }
}
