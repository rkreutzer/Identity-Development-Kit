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

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.session.Command
import com.sphereon.core.compat.JsExportCompat
import com.sphereon.ktor.http.client.provider.HttpClientOptions
import kotlin.experimental.ExperimentalObjCName
import kotlin.native.ObjCName

/**
 * HTTP method for fetching request objects.
 *
 * OpenID4VP 1.0 supports `request_uri_method` parameter to specify the HTTP method.
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("RequestUriMethod", exact = true)
@JsExportCompat
enum class RequestUriMethod {
    /** HTTP GET (default) */
    GET,

    /** HTTP POST */
    POST,
}

/**
 * Arguments for fetching a request object from a remote URI.
 *
 * Per OpenID4VP 1.0 Section 5.10, when `request_uri_method=post`, the wallet can send
 * its metadata and a nonce in the POST request body. This allows the verifier to
 * tailor the authorization request based on the wallet's capabilities.
 *
 * @property requestUri The URI to fetch the request object from (typically HTTPS URL)
 * @property httpMethod HTTP method to use (GET or POST). Defaults to GET per OpenID4VP 1.0
 * @property httpClientOptions Configuration for the HTTP client (SSL, content negotiation, etc.)
 * @property expectedContentType Optional expected content type (e.g., "application/jwt", "application/json")
 * @property walletMetadataJson Optional wallet metadata JSON to send in POST body (for POST method)
 * @property walletNonce Optional nonce to send in POST body for replay protection (for POST method)
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("FetchRequestUriArgs", exact = true)
@JsExportCompat
data class FetchRequestUriArgs(
    val requestUri: String,
    val httpMethod: RequestUriMethod = RequestUriMethod.GET,
    val httpClientOptions: HttpClientOptions = HttpClientOptions.createDefault(),
    val expectedContentType: String? = null,
    val walletMetadataJson: String? = null,
    val walletNonce: String? = null,
)

/**
 * Result of fetching a request object from a remote URI.
 *
 * @property content The fetched content as a string (could be JWT, JSON, or other format)
 * @property contentType The content type returned by the server
 * @property requestUri The original request URI that was fetched
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("FetchedRequestUri", exact = true)
@JsExportCompat
data class FetchedRequestUri(
    val content: String,
    val contentType: String?,
    val requestUri: String,
)

/**
 * Command for fetching request objects from remote URIs.
 *
 * Used in OAuth 2.0 and OpenID Connect for fetching:
 * - JAR (JWT-secured Authorization Request) via `request_uri` parameter
 * - PAR (Pushed Authorization Request) responses
 * - OpenID4VP authorization requests by reference
 *
 * Supports configurable HTTP client options for:
 * - SSL/TLS configuration (mTLS, custom certificates)
 * - Content negotiation (JSON, CBOR, JWT)
 * - Caching and timeout settings
 * - Logging configuration
 *
 * Example usage:
 * ```
 * // Fetch JWT request object
 * val args = FetchRequestUriArgs(
 *     requestUri = "https://verifier.example.com/request/abc123",
 *     httpClientOptions = HttpClientOptions.createDefault(),
 *     expectedContentType = "application/jwt"
 * )
 * val result = fetchRequestUriCommand.execute(args)
 * ```
 *
 * Reference:
 * - RFC 9101 (JAR): https://www.rfc-editor.org/rfc/rfc9101.html
 * - RFC 9126 (PAR): https://www.rfc-editor.org/rfc/rfc9126.html
 * - OpenID4VP 1.0: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("FetchRequestUriCommand", exact = true)
@JsExportCompat
interface FetchRequestUriCommand : Command<FetchRequestUriArgs, FetchedRequestUri, IdkError> {
    companion object {
        const val COMMAND_ID = "http.request.fetch"
    }
}

/**
 * Command service interface for fetching request URIs
 */
@JsExportCompat
@OptIn(ExperimentalObjCName::class)
@ObjCName("FetchRequestUriCommandService", exact = true)
interface FetchRequestUriCommandService {
    suspend fun fetchRequestUri(args: FetchRequestUriArgs): IdkResult<FetchedRequestUri, IdkError>
}
