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

package com.sphereon.ktor.http.client

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.session.ExecutionScopedCommandAdapter
import com.sphereon.di.session.SessionContext
import com.sphereon.di.session.SessionScope
import com.sphereon.ktor.http.client.provider.HttpClientFactory
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding
import io.ktor.client.request.accept
import io.ktor.client.request.forms.FormDataContent
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.Parameters
import io.ktor.http.Url
import io.ktor.http.contentType
import io.ktor.http.isSuccess
import kotlinx.serialization.json.Json

/**
 * Implementation of FetchRequestUriCommand using HttpClientFactory.
 *
 * Fetches request objects from remote URIs with configurable HTTP client options:
 * - HTTP method (GET or POST) per OpenID4VP 1.0 `request_uri_method` parameter
 * - SSL/TLS configuration (mTLS, custom certificates, trust stores)
 * - Content negotiation (JSON, CBOR, plain text)
 * - HTTP caching
 * - Timeouts and retry logic
 * - Custom headers and authentication
 *
 * Validates:
 * - URI scheme must be HTTPS (HTTP allowed only for localhost/127.0.0.1)
 * - Response status must be 2xx
 * - Content type can be validated if expectedContentType is provided
 *
 * Use cases:
 * - RFC 9101 (JAR): Fetch signed JWT request objects
 * - RFC 9126 (PAR): Fetch pushed authorization requests
 * - OpenID4VP: Fetch authorization requests by reference (with GET or POST)
 */
@Inject
@SingleIn(SessionScope::class)
@ContributesBinding(SessionScope::class, binding = binding<FetchRequestUriCommand>())
class FetchRequestUriCommandImpl(
    execution: SessionExecution,
    private val httpClientFactory: HttpClientFactory,
) : ExecutionScopedCommandAdapter<FetchRequestUriArgs, FetchedRequestUri, IdkError>(
        id = FetchRequestUriCommand.COMMAND_ID,
        execution = execution,
    ),
    FetchRequestUriCommand,
    FetchRequestUriCommandService {
    override suspend fun fetchRequestUri(args: FetchRequestUriArgs): IdkResult<FetchedRequestUri, IdkError> = execute(args)

    override suspend fun doExecute(
        args: FetchRequestUriArgs,
        applyDuring: (FetchRequestUriArgs) -> FetchRequestUriArgs,
    ): IdkResult<FetchedRequestUri, IdkError> {
        val processedArgs = applyDuring(args)

        // Validate URI
        val validation = validateRequestUri(processedArgs.requestUri)
        if (validation != null) {
            return Err(validation)
        }

        // Create HTTP client with provided options
        val httpClient =
            try {
                httpClientFactory.createClient(processedArgs.httpClientOptions)
            } catch (expected: Exception) {
                return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message = "Failed to create HTTP client: ${expected.message}",
                        throwable = expected,
                    ),
                )
            }

        return try {
            // Fetch the request object using the specified HTTP method
            val response: HttpResponse =
                when (processedArgs.httpMethod) {
                    RequestUriMethod.GET -> {
                        httpClient.get(processedArgs.requestUri)
                    }

                    RequestUriMethod.POST -> {
                        // OpenID4VP 1.0 Section 5.10 requires form encoding even without optional fields.
                        httpClient.post(processedArgs.requestUri) {
                            accept(ContentType.parse("application/oauth-authz-req+jwt"))
                            setBody(
                                FormDataContent(
                                    Parameters.build {
                                        processedArgs.walletMetadataJson?.let {
                                            Json.parseToJsonElement(it)
                                            append("wallet_metadata", it)
                                        }
                                        processedArgs.walletNonce?.let { append("wallet_nonce", it) }
                                    },
                                ),
                            )
                        }
                    }
                }

            // Validate response status
            if (!response.status.isSuccess()) {
                return Err(
                    IdkError.fromString(
                        message = "Failed to fetch request URI: ${response.status} from ${processedArgs.requestUri}",
                        code = "HTTP_${response.status.value}",
                    ),
                )
            }

            // Get content type
            val contentType = response.contentType()?.toString()

            // Validate content type if expected
            val expectedContentType = processedArgs.expectedContentType
            if (expectedContentType != null && contentType != null) {
                if (!contentType.startsWith(expectedContentType, ignoreCase = true)) {
                    return Err(
                        IdkError.ILLEGAL_ARGUMENT_ERROR(
                            message = "Unexpected content type. Expected: $expectedContentType, Got: $contentType",
                        ),
                    )
                }
            }

            // Read response body as text
            val content = response.bodyAsText()

            if (content.isBlank()) {
                return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message = "Request URI returned empty content",
                    ),
                )
            }

            Ok(
                FetchedRequestUri(
                    content = content,
                    contentType = contentType,
                    requestUri = processedArgs.requestUri,
                ),
            )
        } catch (expected: Exception) {
            Err(
                IdkError.fromString(
                    message = "Failed to fetch request URI: ${expected.message} from ${processedArgs.requestUri}",
                    code = "HTTP_REQUEST_FAILED",
                    exception = expected,
                ),
            )
        } finally {
            // Close the client to free resources
            httpClient.close()
        }
    }

    /**
     * Validates that the request URI is secure and well-formed.
     *
     * Requirements:
     * - Must be HTTPS scheme (HTTP only allowed for localhost/127.0.0.1 for testing)
     * - Must be a valid URL
     *
     * @return IdkError if validation fails, null if valid
     */
    private fun validateRequestUri(requestUri: String): IdkError? {
        if (requestUri.isBlank()) {
            return IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Request URI cannot be blank")
        }

        val url =
            try {
                Url(requestUri)
            } catch (expected: Exception) {
                return IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message = "Invalid request URI: ${expected.message}",
                    throwable = expected,
                )
            }

        // Require HTTPS except for localhost (for testing)
        if (url.protocol.name.lowercase() == "http") {
            val host = url.host.lowercase()
            // RFC 6761: `.localhost` (incl. subdomains) is loopback; http is acceptable.
            if (host != "localhost" && host != "127.0.0.1" && host != "[::1]" && !host.endsWith(".localhost")) {
                return IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message = "Request URI must use HTTPS (HTTP only allowed for localhost). Got: $requestUri",
                )
            }
        } else if (url.protocol.name.lowercase() != "https") {
            return IdkError.ILLEGAL_ARGUMENT_ERROR(
                message = "Request URI must use HTTPS scheme. Got: ${url.protocol.name}",
            )
        }

        return null
    }
}
