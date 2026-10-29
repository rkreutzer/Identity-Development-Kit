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
import com.sphereon.core.api.Ok
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.decodeFromBase64Url
import com.sphereon.core.api.encodeUrlGraph
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.service.TypedServiceCommandAdapter
import com.sphereon.core.api.validation.toIdkResult
import com.sphereon.crypto.core.KeyInfoType
import com.sphereon.crypto.core.ResolvedKeyInfo
import com.sphereon.crypto.jose.jws.JwsJsonGeneral
import com.sphereon.crypto.jose.jws.JwsValidationResult
import com.sphereon.crypto.jose.jws.JwtService
import com.sphereon.crypto.jose.jws.command.VerifyJwsArgs
import com.sphereon.crypto.resolution.AdditionalIdentifierLookup
import com.sphereon.crypto.resolution.extern.ExternalIdentifierDidOpts
import com.sphereon.crypto.resolution.extern.ExternalIdentifierJwksUrlOpts
import com.sphereon.crypto.resolution.extern.ExternalIdentifierResult
import com.sphereon.crypto.resolution.extern.ExternalIdentifierX5cOpts
import com.sphereon.crypto.resolution.extern.MultiExternalIdentifierService
import com.sphereon.di.session.SessionScope
import com.sphereon.ktor.http.client.FetchRequestUriArgs
import com.sphereon.ktor.http.client.FetchRequestUriCommand
import com.sphereon.ktor.http.client.ParseUriQueryCommand
import com.sphereon.ktor.http.client.RequestUriMethod
import com.sphereon.ktor.http.client.getOptional
import com.sphereon.ktor.http.client.getOrDefault
import com.sphereon.ktor.http.client.getRequired
import com.sphereon.ktor.http.client.provider.withCounterpartyEgress
import com.sphereon.ktor.http.client.provider.HttpClientFactory
import com.sphereon.ktor.http.client.provider.HttpClientOptions
import com.sphereon.ktor.http.client.provider.counterpartyEgress
import com.sphereon.oauth2.client.JarService
import com.sphereon.oauth2.client.command.MergeRequestObjectArgs
import com.sphereon.oauth2.common.model.AuthorizationRequest
import com.sphereon.openid.oid4vp.common.ClientIdScheme
import com.sphereon.openid.oid4vp.common.ClientMetadata
import com.sphereon.openid.oid4vp.common.JarConstants
import com.sphereon.openid.oid4vp.common.Oid4vpJson
import com.sphereon.openid.oid4vp.common.Oid4vpRequestTrustMaterialProvider
import com.sphereon.openid.oid4vp.common.qualifyDidJarVerificationMethodId
import com.sphereon.openid.oid4vp.holder.DigitalCredentialsAuthorizationRequest
import com.sphereon.openid.oid4vp.holder.ParseAuthorizationRequestArgs
import com.sphereon.openid.oid4vp.holder.ParseAuthorizationRequestCommand
import com.sphereon.openid.oid4vp.holder.ParseAuthorizationRequestCommandService
import com.sphereon.openid.oid4vp.holder.WalletConfig
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import io.ktor.client.call.body
import io.ktor.client.request.get
import io.ktor.http.HttpStatusCode
import io.ktor.http.Url
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

import dev.zacsweers.metro.ExposeImplBinding
/**
 * Implementation of ParseAuthorizationRequestCommand for OpenID4VP.
 *
 * Parses OpenID4VP authorization request URIs, handling:
 * - Direct request parameters (inline query string)
 * - Request by reference (request_uri parameter)
 * - Request Object (signed JWT)
 *
 * Reference: OpenID4VP 1.0 Section 5.1 - Authorization Request
 *
 * Supported URI formats:
 * - `openid4vp://?client_id=...&...` (direct inline parameters)
 * - `openid4vp://?client_id=...&request_uri=https://...` (request by reference)
 * - `openid4vp://?client_id=...&request=eyJ...` (request object JWT)
 */
@Inject
@SingleIn(SessionScope::class)
@ExposeImplBinding
class ParseAuthorizationRequestCommandImpl(
    execution: SessionExecution,
    private val parseUriQueryCommand: ParseUriQueryCommand,
    private val fetchRequestUriCommand: FetchRequestUriCommand,
    private val jarService: JarService,
    private val httpClientFactory: HttpClientFactory,
    private val externalIdentifierService: MultiExternalIdentifierService,
    private val jwtService: JwtService,
    private val requestTrustMaterialProvider: Oid4vpRequestTrustMaterialProvider,
) : TypedServiceCommandAdapter<ParseAuthorizationRequestArgs, AuthorizationRequest, IdkError>(
        commandId = ParseAuthorizationRequestCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<ParseAuthorizationRequestArgs>(),
        outputTypeToken = typeToken<AuthorizationRequest>(),
    ),
    ParseAuthorizationRequestCommand,
    ParseAuthorizationRequestCommandService {
    override val commandId: String get() = ParseAuthorizationRequestCommand.COMMAND_ID

    override suspend fun supports(args: Any): Boolean = args is ParseAuthorizationRequestArgs

    override suspend fun parseAuthorizationRequest(
        requestUri: String,
        walletConfig: WalletConfig?,
    ): IdkResult<AuthorizationRequest, IdkError> = execute(ParseAuthorizationRequestArgs(requestUri, walletConfig))

    override suspend fun parseDigitalCredentialsAuthorizationRequest(
        request: DigitalCredentialsAuthorizationRequest,
        walletConfig: WalletConfig?,
    ): IdkResult<AuthorizationRequest, IdkError> =
        execute(ParseAuthorizationRequestArgs(walletConfig = walletConfig, digitalCredentialsRequest = request))

    // Everything a holder command fetches runs under the counterparty egress rule, also in the components shared with servers.
    override suspend fun doExecute(
        args: ParseAuthorizationRequestArgs,
        applyDuring: (ParseAuthorizationRequestArgs) -> ParseAuthorizationRequestArgs,
    ): IdkResult<AuthorizationRequest, IdkError> = withCounterpartyEgress { executeUnderEgressRule(args, applyDuring) }

    private suspend fun executeUnderEgressRule(
        args: ParseAuthorizationRequestArgs,
        applyDuring: (ParseAuthorizationRequestArgs) -> ParseAuthorizationRequestArgs,
    ): IdkResult<AuthorizationRequest, IdkError> {
        val processedArgs = applyDuring(args)
        val digitalCredentialsRequest = processedArgs.digitalCredentialsRequest
        return if (digitalCredentialsRequest != null) {
            parseDigitalCredentialsRequest(digitalCredentialsRequest, processedArgs.walletConfig)
        } else {
            parseAuthorizationRequestUri(requireNotNull(processedArgs.requestUri), processedArgs.walletConfig)
        }
    }

    private suspend fun parseAuthorizationRequestUri(
        requestUri: String,
        walletConfig: WalletConfig?,
    ): IdkResult<AuthorizationRequest, IdkError> {

        // Parse URI using dedicated command
        val parsedUri =
            parseUriQueryCommand
                .execute(requestUri)
                .getOrElse { return Err(it) }

        // Validate that query parameters are present
        if (parsedUri.parameters.isEmpty()) {
            return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Invalid authorization request URI: missing query parameters"))
        }

        // Handle Request Objects (JWT) - RFC 9101 (JAR) and OpenID4VP
        // Two methods per RFC 9101:
        // 1. request_uri: JWT fetched from remote URL
        // 2. request: JWT passed inline in query parameter
        val requestUriParam = parsedUri.getFirst("request_uri")
        val requestParam = parsedUri.getFirst("request")

        // OpenID4VP 1.0: request_uri_method specifies HTTP method for fetching request_uri
        // Defaults to "get" if not specified
        val requestUriMethod = parsedUri.getFirst("request_uri_method")?.lowercase() ?: "get"

        // RFC 9101 Section 3.2: The client SHALL NOT use both the request and request_uri parameters
        // in the same authorization request.
        if (requestUriParam != null && requestParam != null) {
            return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "The 'request' and 'request_uri' parameters SHALL NOT be used in the same authorization request"))
        }

        // Resolve the request object JWT (either by fetching from request_uri or using request parameter)
        val requestObjectJwt =
            when {
                // Handle request_uri (fetch remote request object)
                requestUriParam != null -> {
                    // Fetch the request object from the remote URI
                    // Per RFC 9101 Section 3.2: content type SHOULD be application/oauth-authz-req+jwt
                    // OpenID4VP inherits this requirement, though some implementations may vary

                    // Parse HTTP method from request_uri_method parameter (OpenID4VP 1.0)
                    val httpMethod =
                        when (requestUriMethod) {
                            "post" -> {
                                RequestUriMethod.POST
                            }

                            "get" -> {
                                RequestUriMethod.GET
                            }

                            else -> {
                                return Err(
                                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                                        message = "Invalid request_uri_method: $requestUriMethod. Must be 'get' or 'post'",
                                    ),
                                )
                            }
                        }

                    fetchRequestUriCommand
                        .execute(
                            FetchRequestUriArgs(
                                requestUri = requestUriParam,
                                httpMethod = httpMethod,
                                httpClientOptions = HttpClientOptions.createDefault().counterpartyEgress(),
                                expectedContentType = null, // Don't enforce - verify JWT format after fetch
                            ),
                        ).getOrElse { return Err(it) }
                        .content
                }

                // Handle request (inline JWT request object)
                requestParam != null -> {
                    // Per RFC 9101 Section 3.1: The request parameter is a JWT that contains
                    // the authorization request parameters. It can be signed, encrypted, or both.
                    requestParam
                }

                // No request object - use query parameters directly
                else -> {
                    null
                }
            }

        // Merge Request Object parameters with query parameters if present
        val mergedParams =
            if (requestObjectJwt != null) {
                mergeRequestObject(requestObjectJwt, parsedUri.parameters, walletConfig)
                    .getOrElse { return Err(it) }
            } else {
                parsedUri.parameters
            }

        // Note: dcql_query is extracted into additionalParameters below (non-standard params)
        // Actual DCQL parsing and validation happens in ResolveAuthorizationRequestCommand

        // Extract required parameters using extension functions
        val clientId =
            mergedParams
                .getRequired("client_id")
                .getOrElse { return Err(it) }

        // Per OID4VP 1.0: redirect_uri is OPTIONAL when response_mode is direct_post
        // or direct_post.jwt, because response_uri is used instead.
        val responseMode = mergedParams.getOptional("response_mode")
        val responseUriOrBrowserMode =
            responseMode == "direct_post" ||
                responseMode == "direct_post.jwt" ||
                responseMode == "dc_api" ||
                responseMode == "dc_api.jwt"
        val redirectUri =
            if (responseUriOrBrowserMode) {
                mergedParams.getOptional("redirect_uri")
            } else {
                mergedParams
                    .getRequired("redirect_uri")
                    .getOrElse { return Err(it) }
            }

        // Build additional parameters as JsonElements (first value only for each key)
        val standardParams =
            setOf(
                "client_id",
                "response_type",
                "redirect_uri",
                "scope",
                "state",
                "nonce",
                "response_mode",
                "request_uri",
                "request",
                "resource",
                "issuer_state",
                "dpop_jkt",
            )
        val additionalParamsFromRequest =
            mergedParams
                .names()
                .filter { key -> key !in standardParams }
                .associate { key -> key to JsonPrimitive(mergedParams[key] ?: "") }

        if (mergedParams.names().any { it.startsWith(INTERNAL_PARAMETER_PREFIX) }) {
            return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Authorization request contains a reserved internal parameter"))
        }

        val jarParams = requestObjectJwt?.let { extractJarContextParams(it) } ?: emptyMap()

        // Create AuthorizationRequest from merged parameters
        val authRequest =
            AuthorizationRequest(
                clientId = clientId,
                redirectUri = redirectUri,
                responseType = mergedParams.getOrDefault("response_type", "vp_token"),
                scope = mergedParams.getOptional("scope"),
                state = mergedParams.getOptional("state"),
                nonce = mergedParams.getOptional("nonce"),
                responseMode = mergedParams.getOptional("response_mode"),
                requestUri = mergedParams.getOptional("request_uri"),
                request = mergedParams.getOptional("request"),
                resource = mergedParams.getOptional("resource"),
                issuerState = mergedParams.getOptional("issuer_state"),
                dpopJkt = mergedParams.getOptional("dpop_jkt"),
                additionalParameters = additionalParamsFromRequest + jarParams,
            )

        // Semantic validation runs after client authentication in the resolver, so a trusted
        // verifier can receive the protocol error without any credential being prepared.
        return Ok(authRequest)
    }

    private suspend fun parseDigitalCredentialsRequest(
        request: DigitalCredentialsAuthorizationRequest,
        walletConfig: WalletConfig?,
    ): IdkResult<AuthorizationRequest, IdkError> {
        validateDigitalCredentialsOrigin(request.origin)?.let { return Err(it) }
        if (request.data.keys.any { it.startsWith(INTERNAL_PARAMETER_PREFIX) }) {
            return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Digital Credentials request contains a reserved internal parameter"))
        }

        val parsed =
            when (request.protocol) {
                DIGITAL_CREDENTIAL_PROTOCOL_UNSIGNED -> {
                    parseAuthorizationRequestUri(
                        requestUri =
                            authorizationRequestUri(
                                unsignedDigitalCredentialsRequestData(request.data, request.origin),
                            ),
                        walletConfig = walletConfig,
                    ).getOrElse { return Err(it) }
                }

                DIGITAL_CREDENTIAL_PROTOCOL_SIGNED -> {
                    if (request.data.keys != setOf("request")) {
                        return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Signed Digital Credentials data must contain only 'request'"))
                    }
                    val compact = (request.data["request"] as? JsonPrimitive)?.contentOrNull
                    if (compact.isNullOrBlank()) {
                        return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Signed Digital Credentials request is missing compact JWS"))
                    }
                    parseAuthorizationRequestUri(
                        requestUri = "openid4vp://?request=${compact.encodeUrlGraph()}",
                        walletConfig = walletConfig,
                    ).getOrElse { return Err(it) }
                }

                DIGITAL_CREDENTIAL_PROTOCOL_MULTI_SIGNED -> {
                    if (request.data.keys != setOf("request")) {
                        return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Multi-signed Digital Credentials data must contain only 'request'"))
                    }
                    val generalElement = request.data["request"] as? JsonObject
                        ?: return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Multi-signed Digital Credentials request must use JWS JSON General serialization"))
                    val verified = verifyAtLeastOneDigitalCredentialsSignature(generalElement).getOrElse { return Err(it) }
                    if ("client_id" in verified.payload) {
                        return Err(
                            IdkError.ILLEGAL_ARGUMENT_ERROR(
                                message = "Multi-signed Digital Credentials request must carry client_id in each protected header",
                            ),
                        )
                    }
                    val parsedPayload =
                        parseAuthorizationRequestUri(
                            requestUri =
                                authorizationRequestUri(
                                    verified.payload + ("client_id" to JsonPrimitive(verified.clientId)),
                                ),
                            walletConfig = walletConfig,
                        ).getOrElse { return Err(it) }
                    parsedPayload.copy(
                        additionalParameters = parsedPayload.additionalParameters.orEmpty() + jarContextParams(verified.protectedHeader),
                    )
                }

                else ->
                    return Err(
                        IdkError.ILLEGAL_ARGUMENT_ERROR(
                            message = "Unsupported OID4VP Digital Credentials protocol: ${request.protocol}",
                        ),
                    )
            }

        validateDigitalCredentialsAuthorizationRequest(parsed, request)?.let { return Err(it) }
        return Ok(
            parsed.copy(
                additionalParameters =
                    parsed.additionalParameters.orEmpty() +
                        mapOf(
                            DIGITAL_CREDENTIAL_ORIGIN_PARAMETER to JsonPrimitive(request.origin),
                            DIGITAL_CREDENTIAL_PROTOCOL_PARAMETER to JsonPrimitive(request.protocol),
                        ),
            ),
        )
    }

    private suspend fun verifyAtLeastOneDigitalCredentialsSignature(
        element: JsonObject,
    ): IdkResult<VerifiedDigitalCredentialsSignature, IdkError> =
        verifyDigitalCredentialsSignatures(element) { jws ->
            jwtService.verifyJws(VerifyJwsArgs(jws = jws))
        }

    private fun validateDigitalCredentialsAuthorizationRequest(
        parsed: AuthorizationRequest,
        transport: DigitalCredentialsAuthorizationRequest,
    ): IdkError? {
        if (parsed.responseMode != "dc_api" && parsed.responseMode != "dc_api.jwt") {
            return IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Digital Credentials OID4VP request must use response_mode dc_api or dc_api.jwt")
        }
        if (parsed.redirectUri != null || parsed.state != null || parsed.additionalParameters.orEmpty().containsKey("response_uri")) {
            return IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Digital Credentials OID4VP request must not contain redirect_uri, response_uri, or state")
        }
        if (transport.protocol == DIGITAL_CREDENTIAL_PROTOCOL_UNSIGNED) {
            if (parsed.clientId != "origin:${transport.origin}") {
                return IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Unsigned Digital Credentials client identity does not match browser origin")
            }
            return null
        }
        val expectedOrigins = parsed.additionalParameters.orEmpty()["expected_origins"].asStringList()
        if (transport.origin !in expectedOrigins) {
            return IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Digital Credentials expected_origins does not contain the calling browser origin")
        }
        return null
    }

    private fun validateDigitalCredentialsOrigin(origin: String): IdkError? {
        if (origin.isBlank() || '?' in origin || '#' in origin || '@' in origin) {
            return IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Digital Credentials browser origin is invalid")
        }
        val url =
            try {
                Url(origin)
            } catch (expected: Exception) {
                return IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Digital Credentials browser origin is invalid", throwable = expected)
            }
        if (url.protocol.name.lowercase() != "https" || url.host.isBlank() || '/' in origin.substringAfter("://")) {
            return IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Digital Credentials browser origin must be an HTTPS origin without path, query, or fragment")
        }
        return null
    }

    private fun authorizationRequestUri(parameters: Map<String, JsonElement>): String =
        parameters.entries
            .sortedBy { it.key }
            .joinToString(prefix = "openid4vp://?", separator = "&") { (name, value) ->
                "${name.encodeUrlGraph()}=${value.asAuthorizationRequestParameter().encodeUrlGraph()}"
            }

    /**
     * Merges JWT request object parameters with query parameters.
     *
     * Per RFC 9101 Section 3.2: Request Object params take precedence, with specific override rules.
     *
     * JWT validation parameters:
     * - audience: From walletConfig (the expected Request Object JWT `aud` claim)
     * - decryptionKey: From walletConfig (for decrypting JWE request objects)
     * - verificationKey: Should be resolved from client metadata (jwks/jwks_uri)
     *   TODO: Implement client metadata resolution to fetch verificationKey
     *         Requires ResolveAuthorizationRequestCommand with client metadata fetching
     *
     * @param requestObjectJwt The JWT string (signed or encrypted)
     * @param queryParameters The query parameters from the URI
     * @param walletConfig Optional wallet configuration
     * @return Merged parameters or error
     */
    private suspend fun mergeRequestObject(
        requestObjectJwt: String,
        queryParameters: io.ktor.http.Parameters,
        walletConfig: WalletConfig?,
    ): IdkResult<io.ktor.http.Parameters, IdkError> {
        val header = extractJwtHeader(requestObjectJwt)
        val typ = (header["typ"] as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull
        if (typ != JarConstants.JAR_JWT_TYP) {
            return Err(
                IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message = "Request Object typ must be '${JarConstants.JAR_JWT_TYP}'",
                ),
            )
        }
        val payloadHint = extractJwtPayload(requestObjectJwt)
        val kid = header["kid"]?.jsonPrimitive?.contentOrNull
        val x5cHeader =
            (header["x5c"] as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }
        val clientId = queryParameters["client_id"]
        val signedClientId = payloadHint["client_id"]?.jsonPrimitive?.contentOrNull
        if (!clientId.isNullOrBlank() && !signedClientId.isNullOrBlank() && clientId != signedClientId) {
            return Err(
                IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message = "Request object client_id mismatch: outer='$clientId', signed='$signedClientId'",
                ),
            )
        }
        val outerClientIdScheme = queryParameters["client_id_scheme"]?.takeIf { it.isNotBlank() }
        val signedClientIdScheme = payloadHint["client_id_scheme"]?.jsonPrimitive?.contentOrNull?.takeIf { it.isNotBlank() }
        if (outerClientIdScheme != null && signedClientIdScheme != null && outerClientIdScheme != signedClientIdScheme) {
            return Err(
                IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message =
                        "Request object client_id_scheme mismatch: " +
                            "outer='$outerClientIdScheme', signed='$signedClientIdScheme'",
                ),
            )
        }
        val clientMetadata = resolveClientMetadataFromQuery(queryParameters).getOrElse { return Err(it) }
        // The verification key must belong to the client identity the merged request carries. Without
        // an outer client_id that is the signed one: falling back to client_metadata keys would let any
        // key sign a Request Object that claims an X.509 or DID client identifier.
        val verificationKey =
            resolveJarVerificationKey(
                clientId = clientId?.takeIf { it.isNotBlank() } ?: signedClientId,
                clientIdSchemeHint = outerClientIdScheme ?: signedClientIdScheme,
                clientMetadata = clientMetadata,
                requestedKid = kid,
                x5cHeader = x5cHeader,
            ).getOrElse { return Err(it) }

        val mergeArgs =
            MergeRequestObjectArgs(
                requestObjectJwt = requestObjectJwt,
                queryParameters = queryParameters,
                // OpenID4VP 1.0 section 5 makes client_id the Request Object identity
                // binding. An iss claim MAY be present for JAR compatibility, but the Wallet
                // MUST ignore it. Generic OAuth JAR validation remains issuer-aware; this
                // OID4VP profile deliberately opts out of that generic claim check.
                issuer = null,
                audience = oid4vpJarAudience(walletConfig?.audience, payloadHint),
                verificationKey = verificationKey,
                decryptionKey = walletConfig?.decryptionKey, // Wallet decryption key from config
            )

        return jarService
            .mergeRequestObject(mergeArgs)
            .mapError { error ->
                // Map OAuth2Error to IdkError
                IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message = "Failed to merge request object: ${error.message}",
                    throwable = error.exception,
                )
            }.map { it.mergedParameters }
    }

    private fun extractJarContextParams(jwt: String): Map<String, JsonElement> {
        return jarContextParams(extractJwtHeader(jwt))
    }

    private fun jarContextParams(header: JsonObject): Map<String, JsonElement> {
        val kid = header["kid"]?.jsonPrimitive?.contentOrNull
        val typ = header["typ"]?.jsonPrimitive?.contentOrNull
        val x5c =
            header["x5c"]?.let { el ->
                when (el) {
                    is JsonArray -> el
                    else -> null
                }
            }

        return buildMap {
            put("__idk_jar_used", JsonPrimitive(true))
            if (!kid.isNullOrBlank()) {
                put("__idk_jar_kid", JsonPrimitive(kid))
            }
            if (!typ.isNullOrBlank()) {
                put("__idk_jar_typ", JsonPrimitive(typ))
            }
            if (x5c != null) {
                put("__idk_jar_x5c", x5c)
            }
        }
    }

    private fun extractJwtHeader(jwt: String): JsonObject {
        val parts = jwt.split(".")
        if (parts.size < 2) {
            return JsonObject(emptyMap())
        }
        return try {
            val headerJson = parts[0].decodeFromBase64Url().decodeToString()
            Json.parseToJsonElement(headerJson).jsonObject
        } catch (expected: Exception) {
            log.debug("Failed to decode JWT header: ${expected.message}")
            JsonObject(emptyMap())
        }
    }

    /**
     * Decode an unverified Request Object payload solely for verification-key selection hints.
     * No authorization parameter returned by this helper is trusted: [JarService] verifies the
     * JWS before its payload is merged into the request.
     */
    private fun extractJwtPayload(jwt: String): JsonObject {
        val parts = jwt.split(".")
        if (parts.size != 3) {
            return JsonObject(emptyMap())
        }
        return try {
            val payloadJson = parts[1].decodeFromBase64Url().decodeToString()
            Json.parseToJsonElement(payloadJson).jsonObject
        } catch (expected: Exception) {
            log.debug("Failed to decode JWT payload hint: ${expected.message}")
            JsonObject(emptyMap())
        }
    }

    private suspend fun resolveClientMetadataFromQuery(queryParameters: io.ktor.http.Parameters): IdkResult<ClientMetadata?, IdkError> {
        val embedded = queryParameters["client_metadata"]?.trim()
        if (!embedded.isNullOrBlank()) {
            return try {
                Ok(Oid4vpJson.wire.decodeFromString(ClientMetadata.serializer(), embedded))
            } catch (expected: Exception) {
                Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message = "Failed to parse client_metadata JSON: ${expected.message}",
                    ),
                )
            }
        }

        val uri = queryParameters["client_metadata_uri"]?.trim()
        if (uri.isNullOrBlank()) {
            return Ok(null)
        }
        if (!uri.startsWith("https://", ignoreCase = true)) {
            return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "client_metadata_uri must be HTTPS: $uri"))
        }

        return try {
            val httpClient =
                httpClientFactory.createClient(
                    HttpClientOptions(
                        enableContentNegotiation = true,
                    ).counterpartyEgress(),
                )
            val response = httpClient.get(uri)
            if (response.status != HttpStatusCode.OK) {
                return Err(IdkError.UNKNOWN_ERROR(message = "Failed to fetch client_metadata from $uri: HTTP ${response.status.value}"))
            }
            val responseBody = response.body<String>()
            Ok(Oid4vpJson.wire.decodeFromString(ClientMetadata.serializer(), responseBody))
        } catch (expected: Exception) {
            Err(IdkError.UNKNOWN_ERROR(message = "Failed to fetch client_metadata from $uri: ${expected.message}"))
        }
    }

    private suspend fun resolveJarVerificationKey(
        clientId: String?,
        clientIdSchemeHint: String?,
        clientMetadata: ClientMetadata?,
        requestedKid: String?,
        x5cHeader: List<String>?,
    ): IdkResult<KeyInfoType<*>, IdkError> {
        // Per OID4VP 1.0 §5.9.3/§5.10: for prefixed client_ids, the JAR verification key is
        // derived from the client identifier scheme and JOSE header (not client_metadata).
        val effectiveScheme = jarVerificationScheme(clientId, clientIdSchemeHint)
        when (effectiveScheme) {
            ClientIdScheme.DECENTRALIZED_IDENTIFIER -> {
                val rawKid =
                    requestedKid?.takeIf { it.isNotBlank() } ?: return Err(
                        IdkError.ILLEGAL_ARGUMENT_ERROR(message = "DID-bound JAR missing kid header"),
                    )
                // Identity is solely the DID from client_id (§5.9.3). JOSE kid may be an absolute
                // DID URL or a document-relative fragment (`#vm`); qualify relative kids against
                // that DID, then resolve that exact verification-method DID URL. Resolving the
                // bare DID alone picks an arbitrary document key and breaks multi-key did:web
                // hosts that publish issuer + verifier keys together.
                val clientDid =
                    clientId?.let(ClientIdScheme::extractClientIdWithoutScheme)?.takeIf { it.startsWith("did:") }
                        ?: return Err(
                            IdkError.ILLEGAL_ARGUMENT_ERROR(
                                message = "DID-bound JAR requires client_id with decentralized_identifier DID",
                            ),
                        )
                val verificationMethodId =
                    qualifyDidJarVerificationMethodId(clientDid, rawKid)
                        ?: return Err(
                            IdkError.ILLEGAL_ARGUMENT_ERROR(
                                message =
                                    "DID-bound JAR kid must be an absolute DID URL rooted in client_id DID " +
                                        "'$clientDid' or a relative fragment '#…' (got '$rawKid')",
                            ),
                        )
                val resolved =
                    externalIdentifierService
                        .resolve(
                            ExternalIdentifierDidOpts(identifier = verificationMethodId),
                        ).getOrElse { err ->
                            return Err(IdkError.fromString(message = err.message.defaultMessage, code = "DID_KID_RESOLUTION_FAILED"))
                        }
                return Ok(resolved.keyInfo)
            }

            ClientIdScheme.X509_SAN_DNS,
            ClientIdScheme.X509_SAN_URI,
            ClientIdScheme.X509_HASH,
            -> {
                val chain =
                    x5cHeader?.takeIf { it.isNotEmpty() } ?: return Err(
                        IdkError.ILLEGAL_ARGUMENT_ERROR(message = "X.509-bound JAR missing x5c header"),
                    )
                // The transmitted x5c is the identity evidence, never its own trust root.
                // Resolve fresh governed roots at every request-object boundary so disable,
                // removal, rotation, and validity changes are observed immediately.
                val trustMaterial = requestTrustMaterialProvider.resolve().getOrElse {
                    return Err(IdkError.fromString(
                        message = "Governed X.509 request trust material is unavailable",
                        code = "X5C_TRUST_MATERIAL_UNAVAILABLE",
                    ))
                }
                val trustAnchors = trustMaterial.x509.map { it.certificatePem }
                val resolved =
                    externalIdentifierService
                        .resolve(ExternalIdentifierX5cOpts(identifier = chain, verify = true, trustAnchors = trustAnchors))
                        .getOrElse { err ->
                            return Err(IdkError.fromString(message = err.message.defaultMessage, code = "X5C_RESOLUTION_FAILED"))
                        }
                val x5cResolved = resolved as? ExternalIdentifierResult.X5c ?: return Err(
                    IdkError.fromString(
                        message = "X.509 resolution returned an unexpected result type",
                        code = "X5C_RESOLUTION_FAILED",
                    ),
                )
                val verification = x5cResolved.verificationResult
                if (verification.error ||
                    verification.critical ||
                    verification.message == "X509 verification has been disabled" ||
                    verification.publicKey == null
                ) {
                    return Err(
                        IdkError.fromString(
                            message = "X.509 request-object certificate chain validation failed: ${verification.message}",
                            code = "X5C_TRUST_VALIDATION_FAILED",
                        ),
                    )
                }
                return Ok(x5cResolved.keyInfo)
            }

            else -> Unit
        }

        if (clientMetadata == null) {
            return Err(
                IdkError.NOT_FOUND_ERROR(
                    resource = "client_metadata",
                    message = "Cannot verify request object (JAR): missing client_metadata/client_metadata_uri",
                ),
            )
        }

        // Embedded JWKS takes precedence over jwks_uri (per general OIDC conventions).
        val jwks = clientMetadata.jwks
        if (jwks != null) {
            val keys = jwks.keys
            val selected =
                when {
                    !requestedKid.isNullOrBlank() -> keys.firstOrNull { it.kid == requestedKid }
                    else -> keys.firstOrNull()
                } ?: return Err(IdkError.NOT_FOUND_ERROR(message = "No suitable JWK found in client_metadata JWKS (kid='$requestedKid')"))

            return Ok(ResolvedKeyInfo.fromKey(selected))
        }

        val jwksUri =
            clientMetadata.jwksUri
                ?: return Err(IdkError.NOT_FOUND_ERROR(message = "Cannot verify request object (JAR): client_metadata contains neither jwks nor jwks_uri"))

        val resolved =
            externalIdentifierService
                .resolve(
                    ExternalIdentifierJwksUrlOpts(
                        identifier = jwksUri,
                        lookup = AdditionalIdentifierLookup(kid = requestedKid),
                    ),
                ).getOrElse { err ->
                    return Err(IdkError.fromString(message = err.message.defaultMessage, code = "JWKS_URI_RESOLUTION_FAILED"))
                }

        return Ok(resolved.keyInfo)
    }
}

/**
 * OID4VP 1.0 Appendix A.2 requires wallets to ignore `client_id` and `expected_origins`
 * in unsigned DC API requests. The authenticated platform origin supplies the response
 * identity, so a caller-provided client_id must never override it.
 */
internal fun unsignedDigitalCredentialsRequestData(data: JsonObject, origin: String): JsonObject =
    JsonObject(
        data.filterKeys { it != "client_id" && it != "expected_origins" } +
            ("client_id" to JsonPrimitive("origin:$origin")),
    )

internal const val DIGITAL_CREDENTIAL_ORIGIN_PARAMETER: String = "__idk_dc_api_origin"
internal const val DIGITAL_CREDENTIAL_PROTOCOL_PARAMETER: String = "__idk_dc_api_protocol"
private const val INTERNAL_PARAMETER_PREFIX: String = "__idk_"
private const val DIGITAL_CREDENTIAL_PROTOCOL_UNSIGNED: String = "openid4vp-v1-unsigned"
private const val DIGITAL_CREDENTIAL_PROTOCOL_SIGNED: String = "openid4vp-v1-signed"
private const val DIGITAL_CREDENTIAL_PROTOCOL_MULTI_SIGNED: String = "openid4vp-v1-multisigned"
private const val OAUTH_AUTHORIZATION_REQUEST_JWT_TYPE: String = "oauth-authz-req+jwt"

internal data class VerifiedDigitalCredentialsSignature(
    val payload: JsonObject,
    val protectedHeader: JsonObject,
    val clientId: String,
)

internal suspend fun verifyDigitalCredentialsSignatures(
    element: JsonObject,
    verify: suspend (JwsJsonGeneral) -> IdkResult<JwsValidationResult, IdkError>,
): IdkResult<VerifiedDigitalCredentialsSignature, IdkError> {
    val general =
        try {
            Oid4vpJson.wire.decodeFromJsonElement(JwsJsonGeneral.serializer(), element)
        } catch (expected: Exception) {
            return Err(
                IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message = "Invalid JWS JSON General serialization: ${expected.message}",
                    throwable = expected,
                ),
            )
        }
    if (general.signatures.isEmpty()) {
        return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Multi-signed Digital Credentials request has no signatures"))
    }
    val payload =
        try {
            Json.parseToJsonElement(general.payload.decodeFromBase64Url().decodeToString()).jsonObject
        } catch (expected: Exception) {
            return Err(
                IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message = "Multi-signed Digital Credentials request payload is not a JSON object",
                    throwable = expected,
                ),
            )
        }

    val failures = mutableListOf<String>()
    general.signatures.forEachIndexed { index, signature ->
        val protectedHeader =
            try {
                Json.parseToJsonElement(signature.protected.decodeFromBase64Url().decodeToString()).jsonObject
            } catch (_: Exception) {
                failures += "signature $index has an invalid protected header"
                return@forEachIndexed
            }
        val clientId = protectedHeader["client_id"]?.jsonPrimitive?.contentOrNull
        if (clientId.isNullOrBlank()) {
            failures += "signature $index is missing protected client_id"
            return@forEachIndexed
        }
        if (protectedHeader["typ"]?.jsonPrimitive?.contentOrNull != OAUTH_AUTHORIZATION_REQUEST_JWT_TYPE) {
            failures += "signature $index has an invalid typ"
            return@forEachIndexed
        }
        val verification =
            verify(JwsJsonGeneral(payload = general.payload, signatures = listOf(signature))).getOrElse { error ->
                failures += "signature $index could not be verified: ${error.message.defaultMessage}"
                return@forEachIndexed
            }
        if (verification.isValid && verification.trustEstablished && verification.cryptoVerified == true) {
            return Ok(VerifiedDigitalCredentialsSignature(payload, protectedHeader, clientId))
        }
        failures += "signature $index is not trusted and cryptographically valid"
    }
    return Err(
        IdkError.ILLEGAL_ARGUMENT_ERROR(
            message = "No valid signature in multi-signed Digital Credentials request: ${failures.joinToString("; ")}",
        ),
    )
}

private fun JsonElement.asAuthorizationRequestParameter(): String =
    when (this) {
        is JsonPrimitive -> content
        else -> toString()
    }

private fun JsonElement?.asStringList(): List<String> {
    val normalized =
        when (this) {
            is JsonPrimitive ->
                contentOrNull?.let { encoded ->
                    runCatching { Json.parseToJsonElement(encoded) }.getOrNull()
                }
            else -> this
        }
    return (normalized as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }.orEmpty()
}

/** The generic SIOPv2/OID4VP wallet audience verifiers use when the wallet is not pre-registered. */
internal const val OID4VP_SELF_ISSUED_AUDIENCE: String = "https://self-issued.me/v2"

/**
 * The wallet accepts its own configured audience (its client id) AND the generic self-issued
 * audience as the request-object `aud` binding. The (unverified) payload hint only selects which
 * of the two exact values the verified comparison uses, it never widens the comparison itself.
 */
internal fun oid4vpJarAudience(
    configuredAudience: String?,
    payloadHint: JsonObject = JsonObject(emptyMap()),
): String? {
    val hint = payloadHint["aud"]
    val hintValues =
        when (hint) {
            is JsonArray -> hint.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }
            is JsonPrimitive -> listOfNotNull(hint.contentOrNull)
            else -> emptyList()
        }
    return if (OID4VP_SELF_ISSUED_AUDIENCE in hintValues && configuredAudience !in hintValues) {
        OID4VP_SELF_ISSUED_AUDIENCE
    } else {
        configuredAudience
    }
}

/**
 * Resolve only the identity method needed to verify a JAR. A signed payload declaration can
 * select the verification method for ISO 18013-7 requests with a bare client_id, but becomes
 * trusted request data only after the JAR signature has been verified.
 */
internal fun jarVerificationScheme(
    clientId: String?,
    clientIdSchemeHint: String?,
): ClientIdScheme? {
    val prefixedScheme =
        clientId
            ?.let(ClientIdScheme::fromClientId)
            ?.takeUnless { it == ClientIdScheme.PRE_REGISTERED }
    return prefixedScheme ?: ClientIdScheme.fromPrefix(clientIdSchemeHint)
}
