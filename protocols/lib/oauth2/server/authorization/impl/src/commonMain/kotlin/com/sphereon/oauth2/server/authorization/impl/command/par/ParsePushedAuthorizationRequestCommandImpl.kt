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

package com.sphereon.oauth2.server.authorization.impl.command.par

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.service.TypedServiceCommandAdapter
import com.sphereon.di.session.SessionScope
import com.sphereon.oauth2.common.config.OAuth2ServersConfigProvider
import com.sphereon.oauth2.common.config.isEnabled
import com.sphereon.oauth2.common.model.ClientAuthenticationConfig
import com.sphereon.oauth2.common.model.PkceMethod
import com.sphereon.oauth2.common.model.ResponseType
import com.sphereon.oauth2.server.authorization.command.AuthorizationRequestData
import com.sphereon.oauth2.server.authorization.command.ParsePushedAuthorizationRequestArgs
import com.sphereon.oauth2.server.authorization.command.ParsePushedAuthorizationRequestCommand
import com.sphereon.oauth2.server.authorization.command.jar.VerifyRequestObjectArgs
import com.sphereon.oauth2.server.authorization.command.jar.VerifyRequestObjectCommand
import com.sphereon.oauth2.server.authorization.error.AuthorizationServerError
import com.sphereon.oauth2.server.authorization.model.Prompt
import dev.zacsweers.metro.ExposeImplBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import kotlin.experimental.ExperimentalObjCName
import kotlin.native.ObjCName
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject

private const val MIN_PKCE_LENGTH = 43
private const val MAX_PKCE_LENGTH = 128

/**
 * Implementation of ParsePushedAuthorizationRequestCommand
 *
 * Parses Pushed Authorization Requests (PAR) according to RFC 9126.
 *
 * PAR allows clients to push authorization request parameters via HTTP POST to the
 * authorization server before redirecting the user. This provides several benefits:
 * - Request integrity (parameters can't be modified in browser)
 * - Request confidentiality (parameters not visible in redirect)
 * - Support for large requests (no URL length limits)
 * - Client authentication at request time
 *
 * PAR endpoint: POST /par
 * Content-Type: application/x-www-form-urlencoded
 *
 * Request parameters (same as authorization endpoint):
 * - response_type (REQUIRED) - Must be "code"
 * - client_id (REQUIRED) - Client identifier
 * - redirect_uri (OPTIONAL) - Redirection URI
 * - scope (OPTIONAL) - Scope of access request
 * - state (RECOMMENDED) - Opaque value to prevent CSRF
 * - code_challenge (OPTIONAL) - PKCE code challenge
 * - code_challenge_method (OPTIONAL) - PKCE method
 * - Additional extension parameters
 *
 * Response:
 * - request_uri - The request URI to use in authorization request
 * - expires_in - Lifetime of the request URI in seconds (typically 90 seconds)
 *
 * This command performs the same parsing as ParseAuthorizationRequestCommand,
 * but accepts parameters from POST body instead of query string.
 */
@Inject
@SingleIn(SessionScope::class)
@OptIn(ExperimentalObjCName::class)
@ObjCName("ParsePushedAuthorizationRequestCommandImpl", exact = true)
@ExposeImplBinding
class ParsePushedAuthorizationRequestCommandImpl(
    execution: SessionExecution,
    private val verifyRequestObjectCommand: VerifyRequestObjectCommand,
    private val serversConfigProvider: OAuth2ServersConfigProvider,
) : TypedServiceCommandAdapter<ParsePushedAuthorizationRequestArgs, AuthorizationRequestData, IdkError>(
        commandId = ParsePushedAuthorizationRequestCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<ParsePushedAuthorizationRequestArgs>(),
        outputTypeToken = typeToken<AuthorizationRequestData>(),
    ),
    ParsePushedAuthorizationRequestCommand {
    override val commandId: String get() = ParsePushedAuthorizationRequestCommand.COMMAND_ID

    override suspend fun supports(args: Any): Boolean = args is ParsePushedAuthorizationRequestArgs

    override suspend fun doExecute(
        args: ParsePushedAuthorizationRequestArgs,
        applyDuring: (ParsePushedAuthorizationRequestArgs) -> ParsePushedAuthorizationRequestArgs,
    ): IdkResult<AuthorizationRequestData, IdkError> {
        val applied = applyDuring(args)
        return executeInternal(applied.requestBody, applied.clientAuthentication, applied.baseUrlOverride)
            .mapError { IdkError.fromDTO(it) }
    }

    private suspend fun executeInternal(
        requestBody: Map<String, List<String>>,
        clientAuthentication: ClientAuthenticationConfig,
        baseUrlOverride: String?,
    ): IdkResult<AuthorizationRequestData, AuthorizationServerError> {
        // RFC 9126 §2 + RFC 9101 §6: when the PAR body carries a `request` JAR, verify and merge
        // its signed claims onto the body before parsing the rest. The merged single-value map
        // becomes the parser's working set and is what the eventual /authorize?request_uri=urn:...
        // round-trip retrieves. Both `request` and `request_uri` together are forbidden per
        // RFC 9101 §5; PAR specifically forbids `request_uri` already (RFC 9126 §3) but the
        // both-present check still applies if a client smuggles them in.
        val effectiveBody = mergeJarIntoBody(requestBody, baseUrlOverride).getOrElse { return Err(it) }

        return parseEffective(effectiveBody, clientAuthentication)
    }

    private suspend fun mergeJarIntoBody(
        requestBody: Map<String, List<String>>,
        baseUrlOverride: String?,
    ): IdkResult<Map<String, List<String>>, AuthorizationServerError> {
        val rawJar =
            requestBody["request"]?.firstOrNull()?.takeIf { it.isNotBlank() }
                ?: return Ok(requestBody)
        val rawRequestUri = requestBody["request_uri"]?.firstOrNull()?.takeIf { it.isNotBlank() }
        if (rawRequestUri != null) {
            return Err(
                AuthorizationServerError.InvalidRequest(
                    details = "request and request_uri MUST NOT both be present (RFC 9101 §5)",
                ),
            )
        }

        val serverConfig = serversConfigProvider.serverConfig
        if (!serverConfig.jar.isEnabled) {
            return Err(
                AuthorizationServerError.InvalidRequest(
                    details = "JAR (RFC 9101) is disabled on this authorization server",
                ),
            )
        }

        val issuer =
            serverConfig.issuer
                ?: baseUrlOverride
                ?: return Err(
                    AuthorizationServerError.ServerError(
                        details = "Cannot verify JAR audience without an AS issuer",
                    ),
                )

        val frontChannelParameters = requestBody.mapValues { (_, values) -> values.first() }
        val verifyResult =
            verifyRequestObjectCommand.execute(
                VerifyRequestObjectArgs(
                    requestJwt = rawJar,
                    requestUri = null,
                    clientIdHint = requestBody["client_id"]?.firstOrNull(),
                    issuer = issuer,
                    queryParameters = frontChannelParameters,
                ),
            )
        if (verifyResult.isErr) {
            return Err(
                AuthorizationServerError.InvalidRequestObject(
                    details = verifyResult.error.message.defaultMessage,
                ),
            )
        }

        val merged = verifyResult.value.mergedParameters.toMutableMap()
        merged.remove("request")
        merged.remove("request_uri")
        return Ok(merged.mapValues { (_, value) -> listOf(value) })
    }

    private suspend fun parseEffective(
        requestBody: Map<String, List<String>>,
        clientAuthentication: ClientAuthenticationConfig,
    ): IdkResult<AuthorizationRequestData, AuthorizationServerError> {
        // Extract response_type (REQUIRED)
        val responseTypeStr = requestBody["response_type"]?.firstOrNull()
        if (responseTypeStr.isNullOrBlank()) {
            return Err(
                AuthorizationServerError.InvalidRequest(
                    details = "Missing required parameter: response_type",
                ),
            )
        }

        // Parse response_type to List<ResponseType>
        val responseType =
            try {
                responseTypeStr.split(" ").map { type ->
                    when (type.lowercase()) {
                        "code" -> ResponseType.CODE

                        "token" -> ResponseType.TOKEN

                        else -> return Err(
                            AuthorizationServerError.UnsupportedResponseType(
                                responseType = type,
                            ),
                        )
                    }
                }
            } catch (expected: Exception) {
                return Err(
                    AuthorizationServerError.InvalidRequest(
                        details = "Invalid response_type format: ${expected.message}",
                    ),
                )
            }

        // Extract client_id from authentication config
        val clientId =
            when (clientAuthentication) {
                is ClientAuthenticationConfig.Basic -> {
                    clientAuthentication.credentials.clientId
                }

                is ClientAuthenticationConfig.Post -> {
                    clientAuthentication.credentials.clientId
                }

                is ClientAuthenticationConfig.SecretJwt -> {
                    clientAuthentication.assertion.clientId
                }

                is ClientAuthenticationConfig.PrivateKeyJwt -> {
                    clientAuthentication.assertion.clientId
                }

                is ClientAuthenticationConfig.None -> {
                    clientAuthentication.clientId
                }

                is ClientAuthenticationConfig.AttestationJwt -> {
                    // For attestation JWT, client_id comes from request body
                    requestBody["client_id"]?.firstOrNull() ?: return Err(
                        AuthorizationServerError.InvalidRequest(
                            details = "Missing required parameter: client_id",
                        ),
                    )
                }

                is ClientAuthenticationConfig.Anonymous -> {
                    return Err(
                        AuthorizationServerError.InvalidRequest(
                            details = "Anonymous authentication is not allowed for PAR",
                        ),
                    )
                }

                is ClientAuthenticationConfig.MutualTls -> {
                    clientAuthentication.clientId
                }
            }

        if (clientId.isBlank()) {
            return Err(
                AuthorizationServerError.InvalidRequest(
                    details = "Missing required parameter: client_id",
                ),
            )
        }

        // Extract redirect_uri (OPTIONAL but recommended)
        val redirectUri = requestBody["redirect_uri"]?.firstOrNull()

        // Extract scope (OPTIONAL)
        val scope = requestBody["scope"]?.firstOrNull()

        // Extract state (RECOMMENDED for CSRF protection)
        val state = requestBody["state"]?.firstOrNull()

        // Extract PKCE parameters (RFC 7636)
        val codeChallenge = requestBody["code_challenge"]?.firstOrNull()
        val codeChallengeMethodStr = requestBody["code_challenge_method"]?.firstOrNull()

        // Parse code_challenge_method against the AS-advertised allow-list
        // (`pkce_code_challenge_methods_supported`). FAPI2-SP-FINAL §5.2.2-18 forbids `plain`,
        // and operators express that by configuring `pkce-methods-supported: ["S256"]` (the IDK
        // default). Rejecting at PAR ensures the wallet sees `invalid_request` early instead of
        // discovering the policy at /authorize.
        val allowedMethods = serversConfigProvider.serverConfig.pkceMethodsSupported
        val codeChallengeMethod =
            if (codeChallengeMethodStr != null) {
                val canonical =
                    when (codeChallengeMethodStr.uppercase()) {
                        "PLAIN" -> "plain"

                        "S256" -> "S256"

                        else -> return Err(
                            AuthorizationServerError.InvalidRequest(
                                details = "Invalid code_challenge_method: $codeChallengeMethodStr. Must be 'plain' or 'S256'",
                            ),
                        )
                    }
                if (canonical !in allowedMethods) {
                    return Err(
                        AuthorizationServerError.InvalidRequest(
                            details =
                                "code_challenge_method '$canonical' is not in this server's " +
                                    "pkce_code_challenge_methods_supported set: $allowedMethods",
                        ),
                    )
                }
                if (canonical == "plain") PkceMethod.PLAIN else PkceMethod.S256
            } else if (codeChallenge != null) {
                // Default to S256 if code_challenge is present but method is not specified
                PkceMethod.S256
            } else {
                null
            }

        // Validate PKCE parameters
        if (codeChallenge != null) {
            // Verify code_challenge format (RFC 7636 Section 4.2)
            // Must be 43-128 characters, A-Z, a-z, 0-9, -, ., _, ~
            if (codeChallenge.length !in MIN_PKCE_LENGTH..MAX_PKCE_LENGTH) {
                return Err(
                    AuthorizationServerError.InvalidRequest(
                        details = "code_challenge must be 43-128 characters",
                    ),
                )
            }

            // Verify characters are valid (base64url)
            val validChars = Regex("^[A-Za-z0-9._~-]+$")
            if (!validChars.matches(codeChallenge)) {
                return Err(
                    AuthorizationServerError.InvalidRequest(
                        details = "code_challenge contains invalid characters",
                    ),
                )
            }
        }

        // PAR requests should NOT contain request_uri (RFC 9126 Section 3)
        if (requestBody.containsKey("request_uri") && requestBody["request_uri"]?.firstOrNull() != null) {
            return Err(
                AuthorizationServerError.InvalidRequest(
                    details = "request_uri parameter is not allowed in PAR requests",
                ),
            )
        }

        // RFC 9449 §10.1: when a `dpop_jkt` is committed at the PAR endpoint (either by the
        // wallet sending the parameter directly, or by the PAR handler resolving it from a DPoP
        // proof header before delegating to the parser), persist it on the parsed request so
        // the eventual authorization code carries the binding and the token endpoint can refuse
        // a /token request whose DPoP proof signs with a different key.
        val dpopJkt = requestBody["dpop_jkt"]?.firstOrNull()

        // OpenID Connect Core 1.0 §3.1.2.1 request parameters, read as the Authorization Endpoint reads them. The
        // authorization code and the ID Token take them from the pushed request: a dropped `nonce` yields an ID Token
        // without it, and dropped `prompt` / `max_age` / `id_token_hint` would skip the session checks they ask for.
        fun single(name: String): String? = requestBody[name]?.firstOrNull()
        val nonce = single("nonce")
        val responseMode = single("response_mode")
        val prompt = Prompt.parseSpaceSeparated(single("prompt"))
        val display = single("display")
        val loginHint = single("login_hint")
        val idTokenHint = single("id_token_hint")?.takeIf { it.isNotBlank() }
        val acrValues = single("acr_values")?.splitToNonEmpty()
        val uiLocales = single("ui_locales")?.splitToNonEmpty()
        val maxAge =
            single("max_age")?.let { raw ->
                val value = raw.toIntOrNull()
                    ?: return Err(AuthorizationServerError.InvalidRequest(details = "max_age must be a non-negative integer, got: $raw"))
                if (value < 0) return Err(AuthorizationServerError.InvalidRequest(details = "max_age must be non-negative"))
                value
            }
        val claims =
            single("claims")?.let { raw ->
                try {
                    Json.parseToJsonElement(raw) as? JsonObject
                        ?: return Err(AuthorizationServerError.InvalidRequest(details = "claims parameter must be a JSON object"))
                } catch (expected: Exception) {
                    return Err(AuthorizationServerError.InvalidRequest(details = "Malformed claims JSON: ${expected.message}"))
                }
            }

        // Extract additional parameters for extensibility (use first value of each)
        val additionalParameters = requestBody.mapValues { (_, values) -> values.first() }

        // Build authorization request data. Preserve omission as null: redirect_uri is optional
        // when the client has exactly one registered URI, and the verifier resolves that URI.
        // Collapsing omission to an empty string loses the distinction and can later produce a
        // relative `?code=...` redirect against the AS /authorize endpoint.
        return Ok(
            AuthorizationRequestData(
                clientId = clientId,
                redirectUri = redirectUri,
                responseType = responseType,
                scope = scope,
                state = state,
                codeChallenge = codeChallenge,
                codeChallengeMethod = codeChallengeMethod,
                dpopJkt = dpopJkt,
                responseMode = responseMode,
                nonce = nonce,
                display = display,
                prompt = prompt,
                maxAge = maxAge,
                uiLocales = uiLocales,
                idTokenHint = idTokenHint,
                loginHint = loginHint,
                acrValues = acrValues,
                claims = claims,
                requestUri = null, // Not applicable for PAR requests
                additionalParameters = additionalParameters,
            ),
        )
    }
}

private fun String.splitToNonEmpty(): List<String> = split(" ").map { it.trim() }.filter { it.isNotEmpty() }
