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

package com.sphereon.oauth2.server.authorization.impl.command.authorization

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.service.TypedServiceCommandAdapter
import com.sphereon.di.session.SessionScope
import com.sphereon.oauth2.common.model.PkceMethod
import com.sphereon.oauth2.common.model.ResponseType
import com.sphereon.oauth2.server.authorization.command.AuthorizationRequestData
import com.sphereon.oauth2.server.authorization.command.ParseAuthorizationRequestArgs
import com.sphereon.oauth2.server.authorization.command.ParseAuthorizationRequestCommand
import com.sphereon.oauth2.server.authorization.error.AuthorizationServerError
import com.sphereon.oauth2.server.authorization.model.Prompt
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlin.experimental.ExperimentalObjCName
import kotlin.native.ObjCName

private const val MIN_PKCE_LENGTH = 43
private const val MAX_PKCE_LENGTH = 128

/**
 * Implementation of [ParseAuthorizationRequestCommand].
 *
 * Parses OAuth2 / OIDC authorization endpoint requests per RFC 6749 §4.1.1 and OpenID Connect
 * Core 1.0 §3.1.2.1. Extracts **all** parameters that OIDC defines for the authorization
 * request; whether each one is semantically supported is the verifier's concern. Parsing
 * failures are limited to:
 *
 *   - missing required parameters (`response_type`, `client_id`)
 *   - malformed values (PKCE format violations, bad `request_uri` shape, bad `claims` JSON, bad `max_age` integer)
 *
 * Everything else (response-type enforcement, redirect-URI validation, scope policy, PKCE policy,
 * PAR / request-object handling) is deferred to [VerifyAuthorizationRequestCommandImpl].
 *
 * PKCE note: absent `code_challenge_method` is left `null`. RFC 7636 §4.3 defines `plain` as the
 * default, but whether `plain` is acceptable is a server-policy decision belonging in the
 * verifier. Earlier revisions silently upgraded absent-method to `S256`, masking non-compliant
 * clients; we now preserve the wire-absent state.
 *
 * `redirect_uri` is optional at parse time. OAuth2 RFC 6749 §3.1.2.3 / OIDC §3.1.2.1 allow
 * omission when exactly one redirect URI is registered for the client — the verifier resolves
 * it from the client registration in that case.
 */
@Inject
@SingleIn(SessionScope::class)
@OptIn(ExperimentalObjCName::class)
@ObjCName("ParseAuthorizationRequestCommandImpl", exact = true)
class ParseAuthorizationRequestCommandImpl(
    execution: SessionExecution,
) : TypedServiceCommandAdapter<ParseAuthorizationRequestArgs, AuthorizationRequestData, IdkError>(
        commandId = ParseAuthorizationRequestCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<ParseAuthorizationRequestArgs>(),
        outputTypeToken = typeToken<AuthorizationRequestData>(),
    ),
    ParseAuthorizationRequestCommand {
    override val commandId: String get() = ParseAuthorizationRequestCommand.COMMAND_ID

    override suspend fun supports(args: Any): Boolean = args is ParseAuthorizationRequestArgs

    override suspend fun doExecute(
        args: ParseAuthorizationRequestArgs,
        applyDuring: (ParseAuthorizationRequestArgs) -> ParseAuthorizationRequestArgs,
    ): IdkResult<AuthorizationRequestData, IdkError> {
        val applied = applyDuring(args)
        return parseAuthorizationParameters(applied.queryParameters).mapError { IdkError.fromDTO(it) }
    }

}

/** Shared exact parser kernel: also binds process evidence to its signed effective parameters. */
internal fun parseAuthorizationParameters(queryParameters: Map<String, String>): IdkResult<AuthorizationRequestData, AuthorizationServerError> {
        val clientId =
            queryParameters["client_id"]?.takeIf { it.isNotBlank() }
                ?: return Err(AuthorizationServerError.InvalidRequest(details = "Missing required parameter: client_id"))

        // PAR short-circuit: when request_uri carries a PAR URN, the verifier loads the original
        // pushed request from the PAR store. Per OIDC Core §6.2, top-level Authentication Request
        // parameters MAY accompany request_uri — they are fallback / supplementary, with the
        // request object's values taking precedence on conflict. Only `request` is mutually
        // exclusive with `request_uri` (OIDC Core §6.2: "MUST NOT use the request_uri parameter
        // when the request parameter is also present"). Non-PAR request_uri values are NOT
        // rejected here — they pass through so the verifier can emit `request_uri_not_supported`
        // post-redirect once the redirect URI has been validated against the client registration
        // (OIDC §3.1.2.6).
        val requestUri = queryParameters["request_uri"]?.takeIf { it.isNotBlank() }
        if (requestUri != null && requestUri.startsWith("urn:ietf:params:oauth:request_uri:")) {
            if (queryParameters["request"]?.isNotBlank() == true) {
                return Err(
                    AuthorizationServerError.InvalidRequest(
                        details = "request and request_uri are mutually exclusive (OIDC Core §6.2)",
                    ),
                )
            }
            // Surface any URL `response_type` parameter the wallet sent alongside the PAR URN.
            // OIDC Core §6.2 lets the AS treat URL params as supplementary, but FAPI2-SP §5.3.2.1
            // probes (`…-ensure-response-type-token-fails`) expect the AS to detect a conflicting
            // URL `response_type` and reject. The downstream PAR-redeem path compares this list
            // against the PAR-stored `responseType` and surfaces `invalid_request` on mismatch.
            // Empty list means the wallet sent only `client_id + request_uri` and the PAR value
            // is authoritative.
            val frontChannelResponseTypes =
                queryParameters["response_type"]
                    ?.takeIf { it.isNotBlank() }
                    ?.split(" ")
                    ?.map { it.trim() }
                    ?.filter { it.isNotEmpty() }
                    ?.mapNotNull { typeStr ->
                        when (typeStr.lowercase()) {
                            "code" -> ResponseType.CODE
                            "token" -> ResponseType.TOKEN
                            "id_token" -> ResponseType.ID_TOKEN
                            else -> null
                        }
                    }
                    ?: emptyList()
            return Ok(
                AuthorizationRequestData(
                    clientId = clientId,
                    redirectUri = null,
                    responseType = frontChannelResponseTypes,
                    requestUri = requestUri,
                ),
            )
        }

        // response_type — REQUIRED (OIDC §3.1.2.1) but DELIBERATELY NOT enforced here. Missing
        // / empty / unparseable values pass through as `responseType = emptyList()` so the
        // verifier can emit `unsupported_response_type` AFTER client-id + redirect-uri have
        // been validated — that lets the failure ride back to the client's redirect_uri
        // (RFC 6749 §4.1.2.1) instead of stranding the user on the AS error page.
        val responseTypeStr = queryParameters["response_type"]?.takeIf { it.isNotBlank() }.orEmpty()
        val responseTypes =
            responseTypeStr
                .split(" ")
                .map { it.trim() }
                .filter { it.isNotEmpty() }
                .mapNotNull { typeStr ->
                    when (typeStr.lowercase()) {
                        "code" -> ResponseType.CODE
                        "token" -> ResponseType.TOKEN
                        "id_token" -> ResponseType.ID_TOKEN
                        else -> null
                    }
                }

        // redirect_uri — optional at parse time; verifier may require it depending on client registration.
        val redirectUri = queryParameters["redirect_uri"]?.takeIf { it.isNotBlank() }

        val scope = queryParameters["scope"]
        val state = queryParameters["state"]
        val nonce = queryParameters["nonce"]
        val dpopJkt = queryParameters["dpop_jkt"]
        val responseMode = queryParameters["response_mode"]

        // PKCE
        val codeChallenge = queryParameters["code_challenge"]
        val codeChallengeMethodStr = queryParameters["code_challenge_method"]
        val codeChallengeMethod =
            when (codeChallengeMethodStr?.uppercase()) {
                null -> {
                    null
                }

                // absent — verifier applies server policy (default 'plain' per RFC 7636 §4.3)
                "PLAIN" -> {
                    PkceMethod.PLAIN
                }

                "S256" -> {
                    PkceMethod.S256
                }

                else -> {
                    return Err(
                        AuthorizationServerError.InvalidRequest(
                            details = "Invalid code_challenge_method: $codeChallengeMethodStr. Must be 'plain' or 'S256'",
                        ),
                    )
                }
            }
        if (codeChallenge != null) {
            if (codeChallenge.length !in MIN_PKCE_LENGTH..MAX_PKCE_LENGTH) {
                return Err(AuthorizationServerError.InvalidRequest(details = "code_challenge must be 43-128 characters"))
            }
            if (!PKCE_CHAR_REGEX.matches(codeChallenge)) {
                return Err(AuthorizationServerError.InvalidRequest(details = "code_challenge contains invalid characters"))
            }
        }

        // OIDC Core §3.1.2.1 params — parse into the typed model even when unsupported so the
        // verifier can reject with a meaningful error instead of a generic parse failure.
        val prompt = Prompt.parseSpaceSeparated(queryParameters["prompt"])
        val display = queryParameters["display"]
        val loginHint = queryParameters["login_hint"]
        val idTokenHint = queryParameters["id_token_hint"]?.takeIf { it.isNotBlank() }
        val acrValues = queryParameters["acr_values"]?.splitToNonEmpty()
        val uiLocales = queryParameters["ui_locales"]?.splitToNonEmpty()
        // OIDC Core §6 / JAR `request` (Request Object embedded inline). Captured here so the
        // verifier can emit `request_not_supported` post-redirect; we do not process the JWT.
        val requestObject = queryParameters["request"]?.takeIf { it.isNotBlank() }

        val maxAge =
            queryParameters["max_age"]
                ?.let { raw ->
                    raw.toIntOrNull()
                        ?: return Err(AuthorizationServerError.InvalidRequest(details = "max_age must be a non-negative integer, got: $raw"))
                }?.also {
                    if (it < 0) {
                        return Err(AuthorizationServerError.InvalidRequest(details = "max_age must be non-negative"))
                    }
                }

        val claims =
            queryParameters["claims"]?.let { raw ->
                try {
                    Json.parseToJsonElement(raw) as? JsonObject
                        ?: return Err(AuthorizationServerError.InvalidRequest(details = "claims parameter must be a JSON object"))
                } catch (expected: Exception) {
                    return Err(AuthorizationServerError.InvalidRequest(details = "Malformed claims JSON: ${expected.message}"))
                }
            }

        // authorization_details (RFC 9396 / OID4VCI) — validated by verifier
        val authorizationDetails = queryParameters["authorization_details"]
        val resources =
            queryParameters["resource"]?.let { value ->
                val resource = value.trim()
                if (!SECURE_RESOURCE_URI.matches(resource)) {
                    return Err(AuthorizationServerError.InvalidTarget(resource = value, reason = "resource must be a secure absolute URI without a fragment"))
                }
                listOf(resource)
            }.orEmpty()

        return Ok(
            AuthorizationRequestData(
                clientId = clientId,
                redirectUri = redirectUri,
                responseType = responseTypes,
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
                resource = resources,
                request = requestObject,
                requestUri = requestUri,
                claims = claims,
                additionalParameters =
                    buildMap {
                        authorizationDetails?.let { put("authorization_details", it) }
                        queryParameters["issuer_state"]?.takeIf(String::isNotBlank)?.let { put("issuer_state", it) }
                    },
            ),
        )
    }

// base64url alphabet for PKCE code_challenge per RFC 7636 §4.2
private val PKCE_CHAR_REGEX = Regex("^[A-Za-z0-9._~-]+$")

private fun String.splitToNonEmpty(): List<String> = split(" ").map { it.trim() }.filter { it.isNotEmpty() }

private val SECURE_RESOURCE_URI = Regex("^https://[a-z0-9.-]+(?::[0-9]{1,5})?(?:/[^#\\s]*)?$", RegexOption.IGNORE_CASE)
