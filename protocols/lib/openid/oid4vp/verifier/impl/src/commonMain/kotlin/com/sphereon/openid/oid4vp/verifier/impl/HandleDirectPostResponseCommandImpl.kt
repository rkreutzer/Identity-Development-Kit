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

package com.sphereon.openid.oid4vp.verifier.impl

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.conf.PropertyResolver
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.events.EventTypes
import com.sphereon.core.api.service.ServiceCommandRegistry
import com.sphereon.core.api.service.SessionScopedCommandRegistry
import com.sphereon.core.api.service.TypedServiceCommandAdapter
import com.sphereon.core.events.SessionEventService
import com.sphereon.di.session.SessionScope
import com.sphereon.openid.oid4vp.verifier.DirectPostHandledResponse
import com.sphereon.openid.oid4vp.verifier.HandleDirectPostResponseArgs
import com.sphereon.openid.oid4vp.verifier.HandleDirectPostResponseCommand
import com.sphereon.openid.oid4vp.verifier.HandleDirectPostResponseCommandService
import com.sphereon.openid.oid4vp.verifier.ParseAuthorizationResponseArgs
import com.sphereon.openid.oid4vp.verifier.ParseAuthorizationResponseCommand
import com.sphereon.openid.oid4vp.verifier.ValidateAuthorizationResponseArgs
import com.sphereon.openid.oid4vp.verifier.ValidateAuthorizationResponseCommand
import com.sphereon.openid.oid4vp.verifier.hook.PostPresentationHookArgs
import com.sphereon.openid.oid4vp.verifier.impl.hook.PostPresentationHookDispatcher
import com.sphereon.openid.oid4vp.verifier.impl.event.emitOid4vpSessionHistoryEvent
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSession
import com.sphereon.openid.oid4vp.verifier.store.AuthorizationSessionStore
import com.sphereon.openid.oid4vp.verifier.store.ResponseCodeStore
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlin.time.Clock

import dev.zacsweers.metro.ExposeImplBinding
private const val BYTE_MASK = 0xFF
private const val HEX_RADIX = 16
private const val HEX_PAD_LENGTH = 2

/**
 * Implementation of HandleDirectPostResponseCommand for OpenID4VP RP.
 *
 * OpenID4VP 1.0 Section 14.3.3 - Protection of Authorization Response Data:
 *
 * This command handles the direct_post response from the wallet by:
 * 1. Parsing the authorization response (vp_token, state)
 * 2. Generating a unique, cryptographically secure response_code
 * 3. Storing the parsed response in the ResponseCodeStore
 * 4. Returning a redirect_uri with the response_code appended
 *
 * The wallet then redirects the user agent to the redirect_uri.
 * The RP frontend extracts the response_code and uses
 * RetrieveAuthorizationResponseCommand to get the actual response data.
 *
 * Benefits of this pattern:
 * - VP tokens are never exposed in URLs (prevents logging/leakage)
 * - Response codes are single-use (prevents replay attacks)
 * - Response codes expire (limits attack window)
 * - Decouples backend reception from frontend processing
 *
 * Reference: OpenID4VP 1.0 Section 13.3 and 14.3.3
 */
@Inject
@SingleIn(SessionScope::class)
@ExposeImplBinding
class HandleDirectPostResponseCommandImpl(
    execution: SessionExecution,
    private val parseAuthorizationResponseCommand: ParseAuthorizationResponseCommand,
    private val validateAuthorizationResponseCommand: ValidateAuthorizationResponseCommand,
    private val authorizationSessionStore: AuthorizationSessionStore,
    private val responseCodeStore: ResponseCodeStore,
    private val eventService: SessionEventService? = null,
    /**
     * Optional service-command registry for post-presentation hook dispatch.
     * Mirrors [HandleCredentialRequestCommandImpl] on the OID4VCI side: when
     * null (pure-IDK deployment that didn't wire the command-framework registry)
     * no hooks fire — the verifier is a zero-cost no-op at the dispatch site.
     */
    private val serviceCommandRegistry: ServiceCommandRegistry? = null,
    private val sessionScopedCommandRegistry: SessionScopedCommandRegistry? = null,
    /**
     * Optional property resolver so operators can configure which hook
     * command IDs fire at the `oid4vp.after-presentation-validated` extension
     * point. When null the default pattern `hook.post-presentation.**` applies.
     */
    private val propertyResolver: PropertyResolver? = null,
    private val clock: Clock = Clock.System,
) : TypedServiceCommandAdapter<HandleDirectPostResponseArgs, DirectPostHandledResponse, IdkError>(
        commandId = HandleDirectPostResponseCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<HandleDirectPostResponseArgs>(),
        outputTypeToken = typeToken<DirectPostHandledResponse>(),
    ),
    HandleDirectPostResponseCommand,
    HandleDirectPostResponseCommandService {
    override val commandId: String get() = HandleDirectPostResponseCommand.COMMAND_ID
    private var pendingHistorySession: AuthorizationSession? = null

    override suspend fun supports(args: Any): Boolean = args is HandleDirectPostResponseArgs

    override suspend fun handleDirectPostResponse(args: HandleDirectPostResponseArgs): IdkResult<DirectPostHandledResponse, IdkError> = execute(args)

    override suspend fun doExecute(
        args: HandleDirectPostResponseArgs,
        applyDuring: (HandleDirectPostResponseArgs) -> HandleDirectPostResponseArgs,
    ): IdkResult<DirectPostHandledResponse, IdkError> {
        pendingHistorySession = null
        val result = doExecuteInternal(args, applyDuring)
        if (pendingHistorySession != null) {
            emitOutcome(result)
        }
        if (result.isOk) {
            dispatchPostPresentationHooks(args, result.value)
        }
        pendingHistorySession = null
        return result
    }

    /**
     * Post-presentation hook fan-out. Mirrors [HandleCredentialRequestCommandImpl.dispatchPostIssuanceHooks]:
     * resolves registered `hook.post-presentation.**` commands and invokes each
     * one whose `supports` returns true. Per-hook failures are isolated.
     *
     * Pure-IDK deployments that didn't wire `serviceCommandRegistry` /
     * `sessionScopedCommandRegistry` get a zero-cost no-op. EDK / VDX
     * deployments with a registered `hook.post-presentation.*` subscriber
     * (e.g. VDX's `VerifierPresentationConsumeHookCommand` for invitation
     * redemption) see it invoked automatically.
     */
    private suspend fun dispatchPostPresentationHooks(
        args: HandleDirectPostResponseArgs,
        response: DirectPostHandledResponse,
    ) {
        val discovery = serviceCommandRegistry ?: return
        val resolver = sessionScopedCommandRegistry ?: return
        val tenantId = runCatching { execution.sessionContext.context.tenant.tenantId }.getOrNull() ?: return

        // Pull the verifier session by state for the boundInvitationToken etc.
        val correlationId = args.sessionCorrelationId ?: args.originalRequest.state
        val session =
            if (!correlationId.isNullOrBlank()) {
                authorizationSessionStore.get(correlationId).fold(success = { it }, failure = { null })
            } else {
                null
            }

        val hookArgs =
            PostPresentationHookArgs(
                tenantId = tenantId,
                authorizationSessionId = session?.sessionId ?: correlationId,
                transactionId = response.responseCode,
                state = correlationId,
                nonce = args.originalRequest.nonce,
                verifierClientId = args.originalRequest.clientId,
                matchedCredentialsCount = session?.validationResult?.matchedCredentials?.size ?: 0,
                occurredAt = clock.now(),
                boundInvitationToken = session?.boundInvitationToken,
            )

        PostPresentationHookDispatcher(
            resolver = discovery,
            sessionCommands = resolver,
            propertyResolver = propertyResolver,
        ).dispatch(
            args = hookArgs,
            sessionAllowList = session?.postPresentationHookAllowList,
        )
    }

    private suspend fun emitOutcome(result: IdkResult<DirectPostHandledResponse, IdkError>,) {
        if (result.isOk) return
        val es = eventService ?: return
        es.emitOid4vpSessionHistoryEvent(
            type = EventTypes.OID4VP_RESPONSE_FAILED,
            origin = HandleDirectPostResponseCommand.COMMAND_ID,
            session = requireNotNull(pendingHistorySession) {
                "OID4VP direct-post failure has no persisted authorization session"
            },
            stage = "DIRECT_POST",
            outcome = "FAILED",
            errorCode = "authorization_response_failed",
        )
    }

    private suspend fun doExecuteInternal(
        args: HandleDirectPostResponseArgs,
        applyDuring: (HandleDirectPostResponseArgs) -> HandleDirectPostResponseArgs,
    ): IdkResult<DirectPostHandledResponse, IdkError> {
        val processedArgs = applyDuring(args)
        val historyCorrelationId =
            (processedArgs.sessionCorrelationId ?: processedArgs.originalRequest.state)?.takeIf { it.isNotBlank() }
                ?: return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message = "OID4VP direct_post response has no session correlation state",
                    ),
                )
        pendingHistorySession =
            authorizationSessionStore.get(historyCorrelationId).getOrElse { return Err(it) }
                ?: return Err(
                    IdkError.NOT_FOUND_ERROR(
                        resource = "authorizationSession:$historyCorrelationId",
                        message = "OID4VP authorization session not found",
                    ),
                )

        log.debug("Handling direct_post authorization response")
        // Raw form params received from the wallet — the actual authorization response on the wire.
        // Only `response` (when JARM/encrypted) or vp_token / presentation_submission / state are
        // present in the standard direct_post; logging the whole map preserves whatever the wallet sent.
        log.debug(
            "Authorization response (raw form params): " +
                processedArgs.responseParams.entries.joinToString(", ") { (k, v) ->
                    "$k=${if (k == "vp_token" || k == "response") "(length=${v.length})" else v}"
                },
        )
        processedArgs.responseParams["vp_token"]?.let { log.debug("Authorization response vp_token: $it") }
        processedArgs.responseParams["presentation_submission"]?.let {
            log.debug("Authorization response presentation_submission: $it")
        }
        processedArgs.responseParams["response"]?.let {
            log.debug("Authorization response (JARM, length=${it.length}): $it")
        }

        // Step 1: Parse the authorization response
        val parseArgs =
            ParseAuthorizationResponseArgs(
                responseParams = processedArgs.responseParams,
                originalRequest = processedArgs.originalRequest,
                jarmDecryptionKey = processedArgs.jarmDecryptionKey,
                jarmExpectedAudience = processedArgs.jarmExpectedAudience,
                jarmSignerIdentifier = processedArgs.jarmSignerIdentifier,
            )

        val parsedResponse =
            parseAuthorizationResponseCommand
                .execute(parseArgs)
                .getOrElse { error ->
                    log.error("Failed to parse authorization response: ${error.message}")
                    return Err(error)
                }

        log.debug("Parsed authorization response: vpToken queries=${parsedResponse.vpToken.queryIds.size}")
        // Per-query presentations after JARM decryption (if any) — the actual SD-JWT / mdoc
        // payloads the verifier will run holder-binding + DCQL validation against.
        parsedResponse.vpToken.presentations.forEach { (queryId, presentations) ->
            presentations.forEachIndexed { idx, p ->
                log.debug("Parsed vp_token['$queryId'][$idx] (length=${p.length}): $p")
            }
        }

        val responseSession =
            authorizationSessionStore
                .storeResponse(correlationId = historyCorrelationId, parsedResponse = parsedResponse)
                .getOrElse { return Err(it) }
        pendingHistorySession = responseSession
        eventService?.emitOid4vpSessionHistoryEvent(
            type = EventTypes.OID4VP_RESPONSE_RECEIVED,
            origin = HandleDirectPostResponseCommand.COMMAND_ID,
            session = responseSession,
            oldState = null,
            newState = responseSession.status.name,
            stage = "DIRECT_POST",
            outcome = "RECEIVED",
        )

        // Step 2: Validate the authorization response against the DCQL query
        val validateArgs =
            ValidateAuthorizationResponseArgs(
                parsedResponse = parsedResponse,
                originalRequest = processedArgs.originalRequest,
                sessionCorrelationId = processedArgs.sessionCorrelationId,
                dcqlQuery = processedArgs.dcqlQuery,
                expectedNonce = processedArgs.originalRequest.nonce ?: "",
                verifierEncryptionJwkThumbprint = processedArgs.verifierEncryptionJwkThumbprint,
                verifierId = processedArgs.verifierId,
                dcqlQueryId = processedArgs.dcqlQueryId,
                templateId = processedArgs.templateId,
                trustedAuthentications = processedArgs.trustedAuthentications,
                credentialIssuerAuthenticationLookup = processedArgs.credentialIssuerAuthenticationLookup,
                verificationMethodResolutionPolicy = processedArgs.verificationMethodResolutionPolicy,
                mdocDocumentResponseDecryptionKey = processedArgs.mdocDocumentResponseDecryptionKey,
                mdocDocumentResponseEncryptionParameters = processedArgs.mdocDocumentResponseEncryptionParameters,
                mdocDocumentResponseEncryptionProviders = processedArgs.mdocDocumentResponseEncryptionProviders,
                iso18013MdocGeneratedNonce = processedArgs.iso18013MdocGeneratedNonce,
            )

        val validationResult =
            validateAuthorizationResponseCommand
                .execute(validateArgs)
                .getOrElse { error ->
                    log.error("Failed to validate authorization response: ${error.message}")
                    return Err(error)
                }

        if (!validationResult.valid) {
            log.error("Authorization response validation failed: ${validationResult.errors}")
            return Err(
                IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message = "VP token validation failed: ${validationResult.errors.joinToString("; ")}",
                ),
            )
        }

        log.info("Authorization response validated: ${validationResult.matchedCredentials.size} credentials matched")

        // Step 3: Store the parsed response with validation result and generate response_code
        val storeResult =
            responseCodeStore
                .createResponseCode(
                    parsedResponse = parsedResponse,
                    validationResult = validationResult,
                    state = parsedResponse.state,
                    ttlSeconds = processedArgs.responseCodeTtlSeconds,
                ).getOrElse { error ->
                    log.error("Failed to store authorization response: ${error.message}")
                    return Err(error)
                }

        log.debug("Generated response_code, expires at ${storeResult.expiresAt}")

        // Step 4: Build redirect_uri with response_code
        val redirectUri =
            buildRedirectUri(
                baseUri = processedArgs.redirectUri,
                responseCode = storeResult.responseCode,
            )

        log.info("Handled direct_post response, returning redirect_uri with response_code")

        return Ok(
            DirectPostHandledResponse(
                redirectUri = redirectUri,
                responseCode = storeResult.responseCode,
                expiresAt = storeResult.expiresAt,
            ),
        )
    }

    /**
     * Build the redirect URI with response_code in the fragment.
     *
     * Per OID4VP 1.0: the response_code is appended as a URI fragment.
     *
     * Example:
     * - Base: https://client.example.org/cb
     * - Result: https://client.example.org/cb#response_code=091535f699ea575c...
     *
     * @param baseUri The base redirect URI
     * @param responseCode The generated response code
     * @return The complete redirect URI with response_code fragment
     */
    private fun buildRedirectUri(
        baseUri: String,
        responseCode: String,
    ): String {
        val separator = if (baseUri.contains("?")) "&" else "?"
        return "${baseUri}${separator}response_code=${urlEncode(responseCode)}"
    }

    /**
     * URL-encode a string for use in query parameters.
     */
    private fun urlEncode(value: String): String =
        buildString {
            for (char in value) {
                when {
                    char.isLetterOrDigit() || char in "-_.~" -> {
                        append(char)
                    }

                    else -> {
                        val bytes = char.toString().encodeToByteArray()
                        for (byte in bytes) {
                            append('%')
                            append(
                                byte
                                    .toInt()
                                    .and(HEX_BYTE_MASK)
                                    .toString(HEX_RADIX)
                                    .uppercase()
                                    .padStart(2, '0'),
                            )
                        }
                    }
                }
            }
        }

    private companion object {
        private const val HEX_BYTE_MASK = 0xFF
        private const val HEX_RADIX = 16
    }
}
