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
import com.sphereon.core.api.encodeUrlGraph
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.service.TypedServiceCommandAdapter
import com.sphereon.crypto.core.ResolvedKeyInfo
import com.sphereon.crypto.core.jose.Jwk
import com.sphereon.crypto.core.jose.JwkType
import com.sphereon.crypto.core.jose.tryGenerateJwkThumbprint
import com.sphereon.crypto.resolution.AdditionalIdentifierLookup
import com.sphereon.crypto.resolution.extern.JwksKeySelectionPurpose
import com.sphereon.crypto.resolution.extern.ExternalIdentifierJwksUrlOpts
import com.sphereon.crypto.resolution.extern.MultiExternalIdentifierService
import com.sphereon.crypto.resolution.managed.ManagedOptsKeyInfo
import com.sphereon.di.session.SessionScope
import com.sphereon.ktor.http.client.provider.withCounterpartyEgress
import com.sphereon.ktor.http.client.provider.HttpClientFactory
import com.sphereon.ktor.http.client.provider.HttpClientOptions
import com.sphereon.ktor.http.client.provider.counterpartyEgress
import com.sphereon.oauth2.common.jarm.CreateJarmResponseArgs
import com.sphereon.oauth2.common.jarm.CreateJarmResponseCommand
import com.sphereon.oauth2.common.jarm.JarmConfig
import com.sphereon.oauth2.common.jarm.JarmMode
import com.sphereon.oauth2.common.model.AuthorizationResponse
import com.sphereon.oauth2.common.model.AuthorizationErrorResponse
import com.sphereon.openid.oid4vp.common.ResponseMode
import com.sphereon.openid.oid4vp.common.VpToken.Companion.toJson
import com.sphereon.openid.oid4vp.common.responseUri
import com.sphereon.openid.oid4vp.common.selectEncryptedResponseJwk
import com.sphereon.openid.oid4vp.common.vpToken
import com.sphereon.openid.oid4vp.holder.JarmOptions
import com.sphereon.openid.oid4vp.holder.ResolvedOid4vpRequest
import com.sphereon.openid.oid4vp.holder.SubmissionResult
import com.sphereon.openid.oid4vp.holder.SubmitAuthorizationResponseArgs
import com.sphereon.openid.oid4vp.holder.SubmitAuthorizationResponseCommand
import com.sphereon.openid.oid4vp.holder.SubmitAuthorizationResponseCommandService
import com.sphereon.openid.oid4vp.holder.PreparedOid4vpJweRecipientBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import io.ktor.client.request.forms.submitForm
import io.ktor.client.statement.bodyAsText
import io.ktor.http.Parameters
import io.ktor.http.Url
import io.ktor.http.isSuccess
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

import dev.zacsweers.metro.ExposeImplBinding
/**
 * Implementation of SubmitAuthorizationResponseCommand for OpenID4VP.
 *
 * Submits an authorization response to the verifier using the specified response_mode.
 *
 * Reference: OpenID4VP 1.0 Section 8 - Response Modes
 *
 * Supported response modes:
 * - `direct_post`: HTTP POST to response_uri with form-encoded parameters
 *   * Response may contain redirect_uri for next step
 *   * See Section 8.3 - Response Mode: direct_post
 *
 * - `direct_post.jwt`: HTTP POST to response_uri with JWT-encoded response (JARM)
 *   * Response signed/encrypted per client_metadata JARM configuration
 *   * See Section 8.4 - Response Mode: direct_post.jwt
 *   * Requires JarmOptions in args
 *
 * - `fragment`: Redirect to redirect_uri with response in URL fragment
 *   * Format: {redirect_uri}#vp_token=...&state=...
 *   * See Section 8.5 - Response Mode: fragment
 *
 * - `query`: Redirect to redirect_uri with response in query string
 *   * Format: {redirect_uri}?vp_token=...&state=...
 *   * Note: Less common due to URL length limits
 *
 * Error handling:
 * - HTTP errors return SubmissionResult.Error
 * - Network errors return IdkError
 * - Redirect responses return SubmissionResult.Redirect
 */
@Inject
@SingleIn(SessionScope::class)
@ExposeImplBinding
class SubmitAuthorizationResponseCommandImpl(
    execution: SessionExecution,
    private val httpClientFactory: HttpClientFactory,
    private val externalIdentifierService: MultiExternalIdentifierService,
    private val createJarmCommand: CreateJarmResponseCommand,
) : TypedServiceCommandAdapter<SubmitAuthorizationResponseArgs, SubmissionResult, IdkError>(
        commandId = SubmitAuthorizationResponseCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<SubmitAuthorizationResponseArgs>(),
        outputTypeToken = typeToken<SubmissionResult>(),
    ),
    SubmitAuthorizationResponseCommand,
    SubmitAuthorizationResponseCommandService {
    override val commandId: String get() = SubmitAuthorizationResponseCommand.COMMAND_ID

    private val json =
        Json {
            ignoreUnknownKeys = true
            encodeDefaults = true
        }

    override suspend fun supports(args: Any): Boolean = args is SubmitAuthorizationResponseArgs

    override suspend fun submitAuthorizationResponse(
        resolvedRequest: ResolvedOid4vpRequest,
        response: AuthorizationResponse,
        responseMode: ResponseMode?,
        jarmOptions: JarmOptions?,
    ): IdkResult<SubmissionResult, IdkError> =
        execute(SubmitAuthorizationResponseArgs(resolvedRequest, response, responseMode, jarmOptions))

    override suspend fun submitAuthorizationResponse(
        resolvedRequest: ResolvedOid4vpRequest,
        response: AuthorizationResponse,
        responseMode: ResponseMode?,
        jarmOptions: JarmOptions?,
        preparedOid4vpJweRecipientBinding: PreparedOid4vpJweRecipientBinding,
    ): IdkResult<SubmissionResult, IdkError> =
        execute(
            SubmitAuthorizationResponseArgs(
                resolvedRequest,
                response,
                responseMode,
                jarmOptions,
                preparedOid4vpJweRecipientBinding,
            ),
        )

    // Everything a holder command fetches runs under the counterparty egress rule, also in the components shared with servers.
    override suspend fun doExecute(
        args: SubmitAuthorizationResponseArgs,
        applyDuring: (SubmitAuthorizationResponseArgs) -> SubmitAuthorizationResponseArgs,
    ): IdkResult<SubmissionResult, IdkError> = withCounterpartyEgress { executeUnderEgressRule(args, applyDuring) }

    private suspend fun executeUnderEgressRule(
        args: SubmitAuthorizationResponseArgs,
        applyDuring: (SubmitAuthorizationResponseArgs) -> SubmitAuthorizationResponseArgs,
    ): IdkResult<SubmissionResult, IdkError> {
        val processedArgs = applyDuring(args)
        val resolvedRequest = processedArgs.resolvedRequest
        val errorResponse = processedArgs.errorResponse
        if (errorResponse != null && (!processedArgs.resolvedRequest.verifierInfo.clientIdValid ||
                errorResponse.state != processedArgs.resolvedRequest.request.state || errorResponse.additionalParameters.isNotEmpty())) {
            return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Authorization error requires a validated client and the original request state"))
        }
        if (errorResponse == null && processedArgs.resolvedRequest.authorizationError != null) {
            return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "An invalid authorization request cannot receive a credential presentation"))
        }
        val response = processedArgs.response

        // Determine response mode: use override, or request's mode, or default to DIRECT_POST
        val effectiveResponseMode =
            processedArgs.responseMode
                ?: resolvedRequest.request.responseMode?.let { ResponseMode.fromValue(it) }
                ?: ResponseMode.DIRECT_POST

        // A managed mdoc response is signed against this exact OID4VP transcript.
        // Validate the typed binding before dispatching by response mode so a caller
        // cannot downgrade a prepared encrypted response into a plain response path.
        processedArgs.preparedOid4vpJweRecipientBinding?.let { binding ->
            val requestMode = resolvedRequest.request.responseMode ?: ResponseMode.DIRECT_POST.value
            val callerOrigin =
                resolvedRequest.request.additionalParameters[DIGITAL_CREDENTIAL_ORIGIN_PARAMETER]
                    ?.let { (it as? JsonPrimitive)?.contentOrNull }
            if (binding.responseMode !in setOf(ResponseMode.DIRECT_POST_JWT.value, ResponseMode.DC_API_JWT.value) ||
                binding.responseMode != requestMode ||
                binding.responseMode != effectiveResponseMode.value ||
                binding.clientId != resolvedRequest.request.clientId ||
                binding.authorizationRequestNonce != resolvedRequest.request.nonce ||
                binding.responseUri != resolvedRequest.request.responseUri ||
                binding.redirectUri != resolvedRequest.request.redirectUri ||
                binding.callerOrigin != callerOrigin
            ) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "OID4VP request transcript inputs changed after mdoc signing preparation"))
            }
        }

        log.debug("Submitting authorization response with mode: ${effectiveResponseMode.value}")

        return when (effectiveResponseMode) {
            ResponseMode.DIRECT_POST -> {
                submitDirectPost(resolvedRequest, response, errorResponse)
            }

            ResponseMode.DIRECT_POST_JWT -> {
                submitDirectPostJwt(processedArgs)
            }

            ResponseMode.DC_API -> {
                if (errorResponse == null) buildDigitalCredentialResponse(requireNotNull(response)) else digitalCredentialError(errorResponse)
            }

            ResponseMode.DC_API_JWT -> {
                // Appendix A.4 returns a protocol error as a single data.error member, even for dc_api.jwt.
                if (errorResponse != null) digitalCredentialError(errorResponse) else submitDirectPostJwt(processedArgs, digitalCredentialsApi = true)
            }

            ResponseMode.FRAGMENT -> {
                if (errorResponse != null) Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Redirect error submission is not supported"))
                else buildRedirectResponse(resolvedRequest, requireNotNull(response), "#")
            }

            ResponseMode.QUERY -> {
                if (errorResponse != null) Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Redirect error submission is not supported"))
                else buildRedirectResponse(resolvedRequest, requireNotNull(response), "?")
            }

            ResponseMode.IAE_POST, ResponseMode.IAE_POST_JWT -> {
                Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "IAE response modes are not supported for holder submission"))
            }
        }
    }

    private fun digitalCredentialError(error: AuthorizationErrorResponse): IdkResult<SubmissionResult, IdkError> =
        Ok(SubmissionResult.DigitalCredential(buildJsonObject { put("error", JsonPrimitive(error.error)) }))

    private fun authorizationErrorParameters(error: AuthorizationErrorResponse): JsonObject = buildJsonObject {
        put("error", JsonPrimitive(error.error))
        error.errorDescription?.let { put("error_description", JsonPrimitive(it)) }
        error.errorUri?.let { put("error_uri", JsonPrimitive(it)) }
        error.state?.let { put("state", JsonPrimitive(it)) }
    }

    /**
     * Submit authorization response using direct_post mode.
     *
     * Per OpenID4VP 1.0 Section 8.3:
     * - POST to response_uri with form-encoded parameters
     * - Parameters: vp_token, state (no presentation_submission in 1.0 Final)
     * - Response may contain redirect_uri for user redirection
     *
     * @param resolvedRequest The resolved authorization request with response_uri
     * @param response The authorization response containing vp_token
     * @return SubmissionResult with optional redirect_uri
     */
    private suspend fun submitDirectPost(
        resolvedRequest: ResolvedOid4vpRequest,
        response: AuthorizationResponse?,
        errorResponse: AuthorizationErrorResponse? = null,
    ): IdkResult<SubmissionResult, IdkError> {
        // Get response_uri from request
        val responseUri =
            resolvedRequest.request.responseUri
                ?: return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message = "response_uri is required for direct_post mode but not present in request",
                    ),
                )

        // Validate URI
        val validationError = validateUri(responseUri)
        if (validationError != null) {
            return Err(validationError)
        }

        val vpTokenElement = if (errorResponse == null) {
            resolveVpTokenElement(requireNotNull(response))
                ?: return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "vp_token is required in authorization response"))
        } else null
        val formParameters = Parameters.build {
            if (errorResponse != null) {
                authorizationErrorParameters(errorResponse).forEach { (name, value) -> append(name, value.jsonPrimitive.content) }
            } else {
                val success = requireNotNull(response)
                append("vp_token", encodeJsonElement(requireNotNull(vpTokenElement)))
                success.additionalParameters["presentation_submission"]?.let { append("presentation_submission", encodeJsonElement(it)) }
                success.state?.let { append("state", it) }
            }
        }

        // Create HTTP client and POST
        val httpClient =
            try {
                httpClientFactory.createClient(HttpClientOptions.createDefault().counterpartyEgress())
            } catch (expected: Exception) {
                return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message = "Failed to create HTTP client: ${expected.message}",
                        throwable = expected,
                    ),
                )
            }

        return try {
            val httpResponse =
                httpClient.submitForm(
                    url = responseUri,
                    formParameters = formParameters,
                )

            // Handle HTTP response
            if (httpResponse.status.isSuccess()) {
                // Parse response body for redirect_uri
                val responseBody =
                    try {
                        val bodyText = httpResponse.bodyAsText()
                        if (bodyText.isNotBlank()) {
                            json.parseToJsonElement(bodyText).jsonObject
                        } else {
                            null
                        }
                    } catch (expected: Exception) {
                        log.debug("Could not parse response body as JSON: ${expected.message}")
                        null
                    }

                val redirectUri = (responseBody?.get("redirect_uri") as? JsonPrimitive)?.contentOrNull

                log.info(
                    "Authorization response submitted successfully" +
                        if (redirectUri != null) {
                            ", redirect_uri received"
                        } else {
                            ""
                        },
                )

                Ok(
                    SubmissionResult.Success(
                        redirectUri = redirectUri,
                        responseBody = responseBody,
                    ),
                )
            } else {
                // Parse error response per OpenID4VP 1.0 Section 8.3.2
                val errorBody =
                    try {
                        val bodyText = httpResponse.bodyAsText()
                        if (bodyText.isNotBlank()) {
                            json.parseToJsonElement(bodyText).jsonObject
                        } else {
                            null
                        }
                    } catch (_: Exception) {
                        null
                    }

                // `error` is a plain OAuth error string per OID4VP 8.3.2, but server-side error
                // envelopes ({"error": {"code": ..., "message": ...}}) must not crash the holder.
                val errorElement = errorBody?.get("error")
                val error =
                    when (errorElement) {
                        is JsonPrimitive -> errorElement.contentOrNull
                        is JsonObject -> (errorElement["code"] as? JsonPrimitive)?.contentOrNull
                        else -> null
                    } ?: "http_error_${httpResponse.status.value}"
                val errorDescription =
                    (errorBody?.get("error_description") as? JsonPrimitive)?.contentOrNull
                        ?: (errorElement as? JsonObject)?.get("message")?.let { (it as? JsonPrimitive)?.contentOrNull }
                        ?: "HTTP ${httpResponse.status.value}: ${httpResponse.status.description}"

                log.error("Authorization response submission failed: $error - $errorDescription")

                Ok(SubmissionResult.Error(error, errorDescription))
            }
        } catch (expected: Exception) {
            Err(
                IdkError.fromString(
                    message = "Failed to submit authorization response: ${expected.message}",
                    code = "SUBMISSION_FAILED",
                    exception = expected,
                ),
            )
        } finally {
            httpClient.close()
        }
    }

    /**
     * Submit authorization response using direct_post.jwt mode (JARM).
     *
     * Per OpenID4VP 1.0 final response-mode profile:
     * - POST to response_uri with form parameter "response" containing the JWT
     * - The `.jwt` response is unsigned and encrypted; signed-only and nested
     *   signed-plus-encrypted JARM configurations are rejected before JARM creation.
     * - The JWE recipient is checked against the typed mdoc preparation binding when
     *   DeviceAuthentication was prepared for this response.
     *
     * @param args The submission args including JARM options
     * @return SubmissionResult with optional redirect_uri
     */
    private suspend fun submitDirectPostJwt(
        args: SubmitAuthorizationResponseArgs,
        digitalCredentialsApi: Boolean = false,
    ): IdkResult<SubmissionResult, IdkError> {
        val resolvedRequest = args.resolvedRequest
        val response = args.response
        val errorResponse = args.errorResponse
        val jarmOptions = args.jarmOptions

        // Validate JARM options are provided
        if (jarmOptions == null && errorResponse == null) {
            return Err(
                IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message = "jarmOptions is required for direct_post.jwt response mode",
                ),
            )
        }

        // Get response_uri from request
        val responseUri = resolvedRequest.request.responseUri
        if (!digitalCredentialsApi) {
            if (responseUri == null) {
                return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message = "response_uri is required for direct_post.jwt mode but not present in request",
                    ),
                )
            }
            validateUri(responseUri)?.let { return Err(it) }
        }

        val vpTokenElement = if (errorResponse == null) {
            resolveVpTokenElement(requireNotNull(response))
                ?: return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "vp_token is required in authorization response"))
        } else null
        val vpTokenJson = vpTokenElement?.let(::encodeJsonElement)
        val jarmConfig = jarmOptions?.jarmConfig ?: deriveJarmConfigFromClientMetadata(resolvedRequest)
            ?: if (errorResponse != null && !digitalCredentialsApi) {
                return submitDirectPost(resolvedRequest, null, errorResponse)
            } else return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "No response encryption configuration"))

        // OpenID4VP 1.0 §8.3/§8.4's final `.jwt` modes require an unsigned,
        // encrypted response. The same embedded JWK selected while preparing
        // mdoc DeviceAuthentication must also be the key used for this JWE.
        // Reject signed OAuth JARM profiles or key-selection drift before
        // creating/signing any response token.
        val finalOid4vpJwtMode =
            digitalCredentialsApi ||
                args.responseMode == ResponseMode.DIRECT_POST_JWT ||
                resolvedRequest.request.responseMode == ResponseMode.DIRECT_POST_JWT.value
        if (finalOid4vpJwtMode) {
            if (jarmConfig.mode != JarmMode.ENCRYPTED) {
                return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message = "OpenID4VP .jwt response modes require an unsigned encrypted JARM response",
                    ),
                )
            }
        }

        // Validate signing key is present for signing modes
        if ((jarmConfig.mode == JarmMode.SIGNED || jarmConfig.mode == JarmMode.SIGNED_ENCRYPTED) &&
            jarmOptions?.signingKey == null
        ) {
            return Err(
                IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message = "signingKey is required for JARM signing (mode: ${jarmConfig.mode})",
                ),
            )
        }

        // Get verifier's client_id for audience claim
        val audience = resolvedRequest.verifierInfo.clientId

        // Get encryption recipient (verifier's public key) from client metadata (jwks preferred, else jwks_uri)
        val encryptionRecipient =
            if (jarmConfig.mode == JarmMode.ENCRYPTED ||
                jarmConfig.mode == JarmMode.SIGNED_ENCRYPTED
            ) {
                resolveEncryptionRecipient(resolvedRequest, jarmConfig)
                    .getOrElse {
                        if (errorResponse != null && !digitalCredentialsApi) return submitDirectPost(resolvedRequest, null, errorResponse)
                        return Err(it)
                    }
            } else {
                null
            }

        if (finalOid4vpJwtMode) {
            val binding = args.preparedOid4vpJweRecipientBinding
            if (binding != null) {
                val boundJwk =
                    try {
                        json.decodeFromString(Jwk.serializer(), binding.publicJwkJson)
                    } catch (_: Exception) {
                        return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Prepared OID4VP JWE recipient binding contains an invalid public JWK"))
                    }
                if (boundJwk.d != null || boundJwk.k != null || boundJwk.p != null || boundJwk.q != null ||
                    boundJwk.dP != null || boundJwk.dQ != null || boundJwk.qInv != null
                ) {
                    return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Prepared OID4VP JWE recipient binding must contain public key material only"))
                }
                val boundThumbprint = tryGenerateJwkThumbprint(boundJwk).getOrElse { return Err(it) }
                if (boundThumbprint != binding.rfc7638Thumbprint) {
                    return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Prepared OID4VP JWE recipient binding thumbprint is inconsistent"))
                }
                if (binding.keyEncryptionAlgorithm != jarmConfig.encryptionAlgorithm ||
                    binding.contentEncryptionAlgorithm !=
                    (jarmConfig.contentEncryptionAlgorithm ?: JarmConfig.DEFAULT_CONTENT_ENCRYPTION_ALG)
                ) {
                    return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Prepared OID4VP JWE recipient binding algorithms changed after mdoc preparation"))
                }
                val transcriptJwk =
                    resolvedRequest.clientMetadata?.selectEncryptedResponseJwk()
                        ?: return Err(
                            IdkError.ILLEGAL_ARGUMENT_ERROR(
                                message = "OpenID4VP .jwt mdoc responses require the embedded encryption JWK used by DeviceAuthentication",
                            ),
                        )
                if (transcriptJwk.d != null || transcriptJwk.k != null || transcriptJwk.p != null || transcriptJwk.q != null ||
                    transcriptJwk.dP != null || transcriptJwk.dQ != null || transcriptJwk.qInv != null
                ) {
                    return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Verifier encryption JWK must contain public key material only"))
                }
                val transcriptThumbprint = tryGenerateJwkThumbprint(transcriptJwk).getOrElse { return Err(it) }
                if (transcriptThumbprint != binding.rfc7638Thumbprint) {
                    return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Verifier encryption JWK changed after mdoc DeviceAuthentication preparation"))
                }
                if (boundJwk.alg?.value != binding.keyEncryptionAlgorithm ||
                    transcriptJwk.alg?.value != binding.keyEncryptionAlgorithm
                ) {
                    return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Verifier encryption algorithm changed after mdoc DeviceAuthentication preparation"))
                }
            }
            val recipientJwk = encryptionRecipient?.identifier?.key as? JwkType
                ?: return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message = "OpenID4VP .jwt response recipient must be the embedded encryption JWK used by DeviceAuthentication",
                    ),
                )
            val recipientThumbprint = tryGenerateJwkThumbprint(recipientJwk).getOrElse { return Err(it) }
            val preparedBinding = args.preparedOid4vpJweRecipientBinding
            val recipientAlgorithm = recipientJwk.alg?.value
            if (preparedBinding != null &&
                (preparedBinding.rfc7638Thumbprint != recipientThumbprint ||
                    recipientAlgorithm != preparedBinding.keyEncryptionAlgorithm)
            ) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "OpenID4VP .jwt response encryption key does not match the prepared DeviceAuthentication binding"))
            }
        }

        log.debug("Creating JARM authorization response with mode: ${jarmConfig.mode}")

        // Build response parameters for JARM payload
        val responseParameters = errorResponse?.let(::authorizationErrorParameters)
            ?: buildJsonObject {
                put("vp_token", if (finalOid4vpJwtMode) requireNotNull(vpTokenElement) else JsonPrimitive(vpTokenJson))
                requireNotNull(response).additionalParameters["presentation_submission"]?.let { put("presentation_submission", it) }
            }
        // Error responses have no mdoc DeviceAuthentication transcript to bind.
        val headerOverrides = if (errorResponse != null) null else jarmOptions?.protectedHeaderOverrides

        // Create JARM JWT using the generic oauth2 JARM command
        val jarmArgs =
            CreateJarmResponseArgs(
                responseParameters = responseParameters,
                state = errorResponse?.state ?: response?.state,
                issuer = jarmOptions?.issuer,
                audience = audience,
                signingKey = jarmOptions?.signingKey,
                encryptionRecipient = encryptionRecipient,
                jarmConfig = jarmConfig,
                protectedHeaderOverrides = headerOverrides,
                appendStandardJwtClaims = !finalOid4vpJwtMode,
            )

        val jarmResult =
            createJarmCommand.execute(jarmArgs).getOrElse { error ->
                log.error("Failed to create JARM authorization response: ${error.message}")
                if (errorResponse != null && !digitalCredentialsApi) return submitDirectPost(resolvedRequest, null, errorResponse)
                return Err(error)
            }

        if (digitalCredentialsApi) {
            return Ok(
                SubmissionResult.DigitalCredential(
                    buildJsonObject { put("response", JsonPrimitive(jarmResult.jarmJwt)) },
                ),
            )
        }

        requireNotNull(responseUri)

        log.info("Submitting JARM authorization response to: $responseUri (mode: ${jarmResult.mode})")

        // Build form parameters - JARM uses "response" parameter per RFC 9101
        val formParameters =
            Parameters.build {
                append("response", jarmResult.jarmJwt)
            }

        // Create HTTP client and POST
        val httpClient =
            try {
                httpClientFactory.createClient(HttpClientOptions.createDefault().counterpartyEgress())
            } catch (expected: Exception) {
                return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message = "Failed to create HTTP client: ${expected.message}",
                        throwable = expected,
                    ),
                )
            }

        return try {
            val httpResponse =
                httpClient.submitForm(
                    url = responseUri,
                    formParameters = formParameters,
                )

            // Handle HTTP response (same as direct_post)
            if (httpResponse.status.isSuccess()) {
                val responseBody =
                    try {
                        val bodyText = httpResponse.bodyAsText()
                        if (bodyText.isNotBlank()) {
                            json.parseToJsonElement(bodyText).jsonObject
                        } else {
                            null
                        }
                    } catch (expected: Exception) {
                        log.debug("Could not parse response body as JSON: ${expected.message}")
                        null
                    }

                val redirectUri = (responseBody?.get("redirect_uri") as? JsonPrimitive)?.contentOrNull

                log.info(
                    "JARM authorization response submitted successfully" +
                        if (redirectUri != null) {
                            ", redirect_uri received"
                        } else {
                            ""
                        },
                )

                Ok(
                    SubmissionResult.Success(
                        redirectUri = redirectUri,
                        responseBody = responseBody,
                    ),
                )
            } else {
                val errorBody =
                    try {
                        val bodyText = httpResponse.bodyAsText()
                        if (bodyText.isNotBlank()) {
                            json.parseToJsonElement(bodyText).jsonObject
                        } else {
                            null
                        }
                    } catch (_: Exception) {
                        null
                    }

                // `error` is a plain OAuth error string per OID4VP 8.3.2, but server-side error
                // envelopes ({"error": {"code": ..., "message": ...}}) must not crash the holder.
                val errorElement = errorBody?.get("error")
                val error =
                    when (errorElement) {
                        is JsonPrimitive -> errorElement.contentOrNull
                        is JsonObject -> (errorElement["code"] as? JsonPrimitive)?.contentOrNull
                        else -> null
                    } ?: "http_error_${httpResponse.status.value}"
                val errorDescription =
                    (errorBody?.get("error_description") as? JsonPrimitive)?.contentOrNull
                        ?: (errorElement as? JsonObject)?.get("message")?.let { (it as? JsonPrimitive)?.contentOrNull }
                        ?: "HTTP ${httpResponse.status.value}: ${httpResponse.status.description}"

                log.error("JARM authorization response submission failed: $error - $errorDescription")

                Ok(SubmissionResult.Error(error, errorDescription))
            }
        } catch (expected: Exception) {
            Err(
                IdkError.fromString(
                    message = "Failed to submit JARM authorization response: ${expected.message}",
                    code = "JARM_SUBMISSION_FAILED",
                    exception = expected,
                ),
            )
        } finally {
            httpClient.close()
        }
    }

    /**
     * Derive the JARM/JWE config to use for an OID4VP §8.3 encrypted authorization
     * response. OID4VP §8.3 specifies:
     *
     *  - "Implementations MUST use an unsigned, encrypted JWT" — sign-only and
     *    sign+encrypt are JARM-RFC features and are out of scope for OID4VP §8.3.
     *  - "The JWE `alg` algorithm used MUST be equal to the `alg` value of the chosen `jwk`."
     *  - "The JWE `enc` content encryption algorithm used is obtained from the
     *    `encrypted_response_enc_values_supported` parameter of client metadata, …
     *    allowing for the default value of `A128GCM` when not explicitly set."
     *
     * Returns null when client_metadata holds no enc key (no encryption requested).
     */
    private fun deriveJarmConfigFromClientMetadata(resolvedRequest: ResolvedOid4vpRequest): JarmConfig? {
        val clientMetadata = resolvedRequest.clientMetadata ?: return null

        // Pick the first enc-shaped JWK that carries an `alg`. The full key-selection
        // logic (curve preference, multiple keys, jwks_uri fallback) lives in
        // resolveEncryptionRecipient — here we only need to know IF encryption is on
        // and which JWE alg to advertise.
        val encJwk = clientMetadata.selectEncryptedResponseJwk() ?: return null

        val keyAlg = encJwk.alg!!.value
        val contentEnc =
            clientMetadata.encryptedResponseEncValuesSupported?.firstOrNull()
                ?: JarmConfig.DEFAULT_CONTENT_ENCRYPTION_ALG

        return JarmConfig.encrypted(
            keyEncryptionAlg = keyAlg,
            contentEncryptionAlg = contentEnc,
        )
    }

    private suspend fun resolveEncryptionRecipient(
        resolvedRequest: ResolvedOid4vpRequest,
        jarmConfig: JarmConfig,
    ): IdkResult<ManagedOptsKeyInfo, IdkError> {
        if (jarmConfig.mode != JarmMode.ENCRYPTED && jarmConfig.mode != JarmMode.SIGNED_ENCRYPTED) {
            return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "JARM mode does not require encryption recipient: ${jarmConfig.mode}"))
        }

        val clientMetadata =
            resolvedRequest.clientMetadata
                ?: return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "client_metadata is required for JARM encryption but not present"))

        // Prefer an encryption-capable key from embedded JWKS when present. If no suitable key exists there,
        // fall back to resolving jwks_uri via external identifier resolution (it may contain a different key set
        // than the signing/JAR keys).
        // An ISO 18013-7 Annex B verifier advertises the JWE alg in the
        // profile-specific client_metadata member rather than requiring it on
        // every JWK. An explicit JarmConfig therefore permits an embedded
        // encryption key without a JWK alg; regular OID4VP's automatic config
        // derivation still requires the JWK alg.
        val embeddedEncKey = clientMetadata.selectEncryptedResponseJwk(requireAlgorithm = jarmConfig.encryptionAlgorithm == null)

        val selectedKeyInfo =
            when {
                embeddedEncKey != null -> {
                    ResolvedKeyInfo.fromKey(embeddedEncKey)
                }

                else -> {
                    val jwksUri =
                        clientMetadata.jwksUri
                            ?: return Err(
                                IdkError.ILLEGAL_ARGUMENT_ERROR(
                                    message = "No encryption key found in client_metadata jwks and client_metadata jwks_uri is not present",
                                ),
                            )

                    val resolved =
                        externalIdentifierService
                            .resolve(
                                ExternalIdentifierJwksUrlOpts(
                                    identifier = jwksUri,
                                    lookup = AdditionalIdentifierLookup(kid = null),
                                    purpose = JwksKeySelectionPurpose.ENCRYPTION,
                                ),
                            ).getOrElse { err ->
                                return Err(
                                    IdkError.fromString(
                                        message = err.message.defaultMessage,
                                        code = "JWKS_URI_RESOLUTION_FAILED",
                                    ),
                                )
                            }

                    // The resolver has already required one public encryption candidate.
                    resolved.keyInfo
                }
            }

        // JWE recipient needs the verifier public key.
        return Ok(ManagedOptsKeyInfo(identifier = selectedKeyInfo))
    }

    /**
     * Build a redirect response for fragment or query modes.
     *
     * Per OpenID4VP 1.0 Section 8.5/8.6:
     * - Encode response parameters in URL
     * - Use fragment (#) or query (?) separator
     *
     * @param resolvedRequest The resolved authorization request with redirect_uri
     * @param response The authorization response containing vp_token
     * @param separator "#" for fragment mode, "?" for query mode
     * @return SubmissionResult.Redirect with complete redirect URI
     */
    private fun buildRedirectResponse(
        resolvedRequest: ResolvedOid4vpRequest,
        response: AuthorizationResponse,
        separator: String,
    ): IdkResult<SubmissionResult, IdkError> {
        // Get redirect_uri from request
        val redirectUri = resolvedRequest.request.redirectUri
        if (redirectUri.isNullOrBlank()) {
            return Err(
                IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message = "redirect_uri is required for fragment/query mode but not present in request",
                ),
            )
        }

        // Validate URI
        val validationError = validateUri(redirectUri)
        if (validationError != null) {
            return Err(validationError)
        }

        // Get VP token from response
        val vpTokenElement =
            resolveVpTokenElement(response)
                ?: return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message = "vp_token is required in authorization response",
                    ),
                )
        val vpTokenJson = encodeJsonElement(vpTokenElement)
        val presentationSubmissionElement = response.additionalParameters["presentation_submission"]

        // Build redirect URI with parameters
        val fullRedirectUri =
            buildString {
                append(redirectUri)

                // Handle case where redirect_uri already has query params
                if (separator == "?") {
                    append(
                        if (redirectUri.contains("?")) {
                            "&"
                        } else {
                            "?"
                        }
                    )
                } else {
                    append(separator)
                }

                append("vp_token=")
                append(vpTokenJson.encodeUrlGraph())

                presentationSubmissionElement?.let {
                    append("&presentation_submission=")
                    append(encodeJsonElement(it).encodeUrlGraph())
                }
                response.state?.let {
                    append("&state=")
                    append(it.encodeUrlGraph())
                }
            }

        val modeName =
            if (separator == "#") {
                "fragment"
            } else {
                "query"
            }
        log.info("Built $modeName redirect response")

        return Ok(SubmissionResult.Redirect(redirectUri = fullRedirectUri))
    }

    /**
     * Validates that the URI is secure and well-formed.
     *
     * Requirements:
     * - Must be HTTPS scheme (HTTP only allowed for localhost/127.0.0.1 for testing)
     * - Must be a valid URL
     *
     * @return IdkError if validation fails, null if valid
     */
    private fun validateUri(uri: String): IdkError? {
        if (uri.isBlank()) {
            return IdkError.ILLEGAL_ARGUMENT_ERROR(message = "URI cannot be blank")
        }

        val url =
            try {
                Url(uri)
            } catch (expected: Exception) {
                return IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message = "Invalid URI: ${expected.message}",
                    throwable = expected,
                )
            }

        // Require HTTPS except for localhost (for testing)
        if (url.protocol.name.lowercase() == "http") {
            val host = url.host.lowercase()
            // RFC 6761: `.localhost` (incl. subdomains) is loopback; http is acceptable.
            if (host != "localhost" && host != "127.0.0.1" && host != "[::1]" && !host.endsWith(".localhost")) {
                return IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message = "URI must use HTTPS (HTTP only allowed for localhost). Got: $uri",
                )
            }
        } else if (url.protocol.name.lowercase() != "https") {
            return IdkError.ILLEGAL_ARGUMENT_ERROR(
                message = "URI must use HTTPS scheme. Got: ${url.protocol.name}",
            )
        }

        return null
    }

    private fun resolveVpTokenElement(response: AuthorizationResponse): JsonElement? {
        response.vpToken?.let { return it.toJson() }
        return response.additionalParameters["vp_token"]
    }

    private fun buildDigitalCredentialResponse(response: AuthorizationResponse): IdkResult<SubmissionResult, IdkError> {
        val vpToken =
            resolveVpTokenElement(response)
                ?: return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message = "vp_token is required in Digital Credentials API authorization response",
                    ),
                )
        return Ok(
            SubmissionResult.DigitalCredential(
                buildJsonObject {
                    put("vp_token", vpToken)
                    response.additionalParameters.forEach { (name, value) -> put(name, value) }
                    response.state?.let { put("state", JsonPrimitive(it)) }
                },
            ),
        )
    }

    private fun encodeJsonElement(element: JsonElement): String = json.encodeToString(JsonElement.serializer(), element)
}
