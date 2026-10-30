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

package com.sphereon.openid.oid4vp.holder.impl

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.asErrorResult
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.error.IdkErrorType
import com.sphereon.core.api.session.asCoreApiServiceGraph
import com.sphereon.core.defaults.app.staticMinimalTestAppGraph
import com.sphereon.crypto.resolution.IIdentifierMethod
import com.sphereon.crypto.jose.jws.JwsJsonFlattened
import com.sphereon.crypto.jose.jws.JwsJsonGeneral
import com.sphereon.crypto.jose.jws.JwsValidationResult
import com.sphereon.crypto.jose.jws.JwtCompactResult
import com.sphereon.crypto.jose.jws.JwtService
import com.sphereon.crypto.jose.jws.PreparedJwsObject
import com.sphereon.crypto.jose.jws.command.CreateJwsArgs
import com.sphereon.crypto.jose.jws.command.CreateJwsJsonArgs
import com.sphereon.crypto.jose.jws.command.VerifyJwsArgs
import com.sphereon.crypto.resolution.extern.ExternalIdentifierOpts
import com.sphereon.crypto.resolution.extern.ExternalIdentifierOptsOrResult
import com.sphereon.crypto.resolution.extern.ExternalIdentifierResult
import com.sphereon.crypto.resolution.extern.MultiExternalIdentifierService
import com.sphereon.ktor.http.client.FetchRequestUriCommandImpl
import com.sphereon.ktor.http.client.ParseUriQueryCommandImpl
import com.sphereon.oauth2.client.JarService
import com.sphereon.openid.oid4vp.common.impl.UnavailableOid4vpRequestTrustMaterialProvider
import com.sphereon.openid.oid4vp.holder.DigitalCredentialsAuthorizationRequest
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Simple test to debug ParseAuthorizationRequestCommandImpl
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SimpleParseTest {
    @Test
    fun `test basic parse`() =
        runTest {
            val app = staticMinimalTestAppGraph(this, "test-app", "test", "1.0.0")
            val user = app.userContextManager.getAnonymous()
            val session = user.sessionContextManager.getAnonymous()
            val execution = session.asCoreApiServiceGraph().serviceExecution
            val jwtService = unsupportedJwtService

            // Create real instances
            val httpClientFactory =
                object : com.sphereon.ktor.http.client.provider.HttpClientFactory {
                    override fun createClient(options: com.sphereon.ktor.http.client.provider.HttpClientOptions) = io.ktor.client.HttpClient()

                    override fun isSupportedOptions(options: com.sphereon.ktor.http.client.provider.HttpClientOptions) = true

                    override fun getEngineTypesSupported() = listOf(com.sphereon.ktor.http.client.provider.HttpClientEngineType.CIO)

                    override fun getEngineTypeDefault() = com.sphereon.ktor.http.client.provider.HttpClientEngineType.CIO
                }

            val fetchCommand = FetchRequestUriCommandImpl(execution, httpClientFactory)
            val parseUriCommand = ParseUriQueryCommandImpl(execution)

            // Mock JAR service
            val mockJarService =
                object : JarService {
                    override suspend fun createSignedJar(args: com.sphereon.oauth2.client.command.CreateSignedJarArgs) =
                        com.sphereon.core.api
                            .Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "not impl"))

                    override suspend fun createEncryptedJar(args: com.sphereon.oauth2.client.command.CreateEncryptedJarArgs) =
                        com.sphereon.core.api
                            .Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "not impl"))

                    override suspend fun parseJar(args: com.sphereon.oauth2.client.command.ParseJarArgs) =
                        com.sphereon.core.api
                            .Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "not impl"))

                    override suspend fun mergeRequestObject(args: com.sphereon.oauth2.client.command.MergeRequestObjectArgs) =
                        com.sphereon.core.api
                            .Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "not impl"))

                    override val commands: JarService.Commands
                        get() = TODO("Not needed")
                }

            // Mock external identifier service
            val mockExternalIdentifierService =
                object : MultiExternalIdentifierService {
                    override val supportedIdentifierMethods: List<IIdentifierMethod> = emptyList()

                    override suspend fun isSupportedIdentifier(identifier: Any): Boolean = false

                    override suspend fun isSupportedIdentifierMethod(identifierMethod: IIdentifierMethod): Boolean = false

                    override suspend fun isSupportedOpts(opts: ExternalIdentifierOptsOrResult): Boolean = false

                    override suspend fun asSupportedOpts(opts: ExternalIdentifierOptsOrResult): IdkResult<ExternalIdentifierOpts, IdkErrorType> =
                        IdkError.COMMAND_ARG_NOT_SUPPORTED_ERROR(message = "Not implemented in test").asErrorResult()

                    override suspend fun resolve(opts: ExternalIdentifierOptsOrResult): IdkResult<ExternalIdentifierResult, IdkErrorType> =
                        IdkError.COMMAND_ARG_NOT_SUPPORTED_ERROR(message = "Not implemented in test").asErrorResult()
                }

            val command =
                ParseAuthorizationRequestCommandImpl(
                    execution = execution,
                    parseUriQueryCommand = parseUriCommand,
                    fetchRequestUriCommand = fetchCommand,
                    jarService = mockJarService,
                    httpClientFactory = httpClientFactory,
                    externalIdentifierService = mockExternalIdentifierService,
                    jwtService = jwtService,
                    requestTrustMaterialProvider = UnavailableOid4vpRequestTrustMaterialProvider(),
                )

            // Simple test - use longer nonce (min 8 chars)
            val result =
                command.parseAuthorizationRequest(
                    requestUri = "openid4vp://?client_id=test&redirect_uri=https://example.com&response_type=vp_token&nonce=test123456",
                    walletConfig = null,
                )

            println("Result: $result")
            if (result is com.sphereon.core.api.Err) {
                println("ERROR: ${result.error.message.defaultMessage}")
            }

            assertTrue(result is Ok, "Result should be Ok")
            val request = (result as Ok).value
            assertEquals("test", request.clientId)

            val browserRequest =
                command.parseDigitalCredentialsAuthorizationRequest(
                    request =
                        DigitalCredentialsAuthorizationRequest(
                            protocol = "openid4vp-v1-unsigned",
                            origin = "https://wallet.example.com",
                            data =
                                buildJsonObject {
                                    put("response_type", "vp_token")
                                    put("response_mode", "dc_api")
                                    put("nonce", "nonce-12345678")
                                    put("dcql_query", "{\"credentials\":[]}")
                                },
                        ),
                    walletConfig = null,
                )
            assertTrue(browserRequest is Ok, browserRequest.toString())
            val parsedBrowserRequest = (browserRequest as Ok).value
            assertEquals("origin:https://wallet.example.com", parsedBrowserRequest.clientId)
            assertEquals(
                "https://wallet.example.com",
                parsedBrowserRequest.additionalParameters?.get(DIGITAL_CREDENTIAL_ORIGIN_PARAMETER)?.jsonPrimitive?.content,
            )

            val unsignedRequestWithCallerIdentityFields =
                command.parseDigitalCredentialsAuthorizationRequest(
                    request =
                        DigitalCredentialsAuthorizationRequest(
                            protocol = "openid4vp-v1-unsigned",
                            origin = "https://wallet.example.com",
                            data =
                                buildJsonObject {
                                    put("client_id", "origin:https://attacker.example")
                                    put("expected_origins", "https://attacker.example")
                                    put("response_type", "vp_token")
                                    put("response_mode", "dc_api")
                                    put("nonce", "nonce-12345678")
                                    put("dcql_query", "{\"credentials\":[]}")
                                },
                        ),
                    walletConfig = null,
                )
            assertTrue(unsignedRequestWithCallerIdentityFields is Ok, unsignedRequestWithCallerIdentityFields.toString())
            val callerIdentityIgnored = (unsignedRequestWithCallerIdentityFields as Ok).value
            assertEquals("origin:https://wallet.example.com", callerIdentityIgnored.clientId)
            assertTrue("expected_origins" !in callerIdentityIgnored.additionalParameters.orEmpty())
        }
}

private val unsupportedJwtService: JwtService =
    object : JwtService {
        override val commands: JwtService.Commands
            get() = error("JWS commands are not used by these unsigned parsing tests")

        override fun assembleJwsGeneral(
            prepared: PreparedJwsObject,
            signatureBytes: ByteArray,
        ): JwsJsonGeneral = error("JWS creation is not used by these unsigned parsing tests")

        override fun assembleJwsFlattened(
            prepared: PreparedJwsObject,
            signatureBytes: ByteArray,
        ): JwsJsonFlattened = error("JWS creation is not used by these unsigned parsing tests")

        override fun assembleJwsCompact(
            prepared: PreparedJwsObject,
            signatureBytes: ByteArray,
        ): JwtCompactResult = error("JWS creation is not used by these unsigned parsing tests")

        override suspend fun prepareJws(args: CreateJwsJsonArgs): IdkResult<PreparedJwsObject, IdkError> =
            error("JWS creation is not used by these unsigned parsing tests")

        override suspend fun createJwsCompact(args: CreateJwsArgs): IdkResult<JwtCompactResult, IdkError> =
            error("JWS creation is not used by these unsigned parsing tests")

        override suspend fun createJwsJsonFlattened(args: CreateJwsJsonArgs): IdkResult<JwsJsonFlattened, IdkError> =
            error("JWS creation is not used by these unsigned parsing tests")

        override suspend fun createJwsJsonGeneral(args: CreateJwsJsonArgs): IdkResult<JwsJsonGeneral, IdkError> =
            error("JWS creation is not used by these unsigned parsing tests")

        override suspend fun verifyJws(args: VerifyJwsArgs): IdkResult<JwsValidationResult, IdkError> =
            error("JWS verification is not used by these unsigned parsing tests")
    }
