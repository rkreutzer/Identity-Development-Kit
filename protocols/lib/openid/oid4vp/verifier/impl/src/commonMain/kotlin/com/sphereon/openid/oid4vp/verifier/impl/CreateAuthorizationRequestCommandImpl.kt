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
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.events.EventTypes
import com.sphereon.core.api.service.TypedServiceCommandAdapter
import com.sphereon.core.events.SessionEventService
import com.sphereon.di.session.SessionScope
import com.sphereon.openid.oid4vp.common.ClientIdScheme
import com.sphereon.openid.oid4vp.common.ResponseMode
import com.sphereon.openid.oid4vp.common.buildOid4vpAuthorizationRequest
import com.sphereon.openid.oid4vp.dcql.DcqlQuery
import com.sphereon.openid.oid4vp.dcql.validateDcqlQuery
import com.sphereon.openid.oid4vp.verifier.CreateAuthorizationRequestArgs
import com.sphereon.openid.oid4vp.verifier.CreateAuthorizationRequestCommand
import com.sphereon.openid.oid4vp.verifier.CreateAuthorizationRequestCommandService
import com.sphereon.openid.oid4vp.verifier.CreatedAuthorizationRequest
import com.sphereon.openid.oid4vp.verifier.impl.event.emitOid4vpSessionHistoryEvent
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSession
import com.sphereon.openid.oid4vp.verifier.model.Oid4vpSessionIdentity
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSessionStatus
import com.sphereon.openid.oid4vp.verifier.requesturi.RequestObjectSigningConfig
import com.sphereon.openid.oid4vp.verifier.store.AuthorizationSessionStore
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import io.konform.validation.Invalid
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import kotlin.time.Clock
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

import dev.zacsweers.metro.ExposeImplBinding
/**
 * Implementation of CreateAuthorizationRequestCommand for OpenID4VP RP (Verifier).
 *
 * Creates authorization requests with:
 * - DCQL query
 * - Client metadata (embedded or by reference)
 * - Response mode configuration (direct_post, fragment, query)
 * - Client ID scheme (redirect_uri, did, x509_san_dns, etc.)
 * - Nonce for holder binding verification
 *
 * Reference: OpenID4VP 1.0 Final Section 5 - Authorization Request
 */
@OptIn(ExperimentalUuidApi::class)
@Inject
@SingleIn(SessionScope::class)
@ExposeImplBinding
class CreateAuthorizationRequestCommandImpl(
    execution: SessionExecution,
    private val authorizationSessionStore: AuthorizationSessionStore,
    private val requestObjectSigningConfig: RequestObjectSigningConfig,
    private val eventService: SessionEventService? = null,
) : TypedServiceCommandAdapter<CreateAuthorizationRequestArgs, CreatedAuthorizationRequest, IdkError>(
        commandId = CreateAuthorizationRequestCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<CreateAuthorizationRequestArgs>(),
        outputTypeToken = typeToken<CreatedAuthorizationRequest>(),
    ),
    CreateAuthorizationRequestCommand,
    CreateAuthorizationRequestCommandService {
    override val commandId: String get() = CreateAuthorizationRequestCommand.COMMAND_ID
    private var pendingHistorySession: AuthorizationSession? = null

    override suspend fun supports(args: Any): Boolean = args is CreateAuthorizationRequestArgs

    override suspend fun createAuthorizationRequest(args: CreateAuthorizationRequestArgs): IdkResult<CreatedAuthorizationRequest, IdkError> = execute(args)

    override suspend fun doExecute(
        args: CreateAuthorizationRequestArgs,
        applyDuring: (CreateAuthorizationRequestArgs) -> CreateAuthorizationRequestArgs,
    ): IdkResult<CreatedAuthorizationRequest, IdkError> {
        pendingHistorySession = null
        val result = doExecuteInternal(args, applyDuring)
        emitOutcome(result)
        pendingHistorySession = null
        return result
    }

    private suspend fun emitOutcome(
        result: IdkResult<CreatedAuthorizationRequest, IdkError>,
    ) {
        if (!result.isOk) return
        val es = eventService ?: return
        es.emitOid4vpSessionHistoryEvent(
            type = EventTypes.OID4VP_REQUEST_CREATED,
            origin = CreateAuthorizationRequestCommand.COMMAND_ID,
            session = requireNotNull(pendingHistorySession) {
                "Created OID4VP request has no persisted authorization session"
            },
            oldState = null,
            newState = AuthorizationSessionStatus.AUTHORIZATION_REQUEST_CREATED.name,
            stage = "REQUEST_CREATED",
            outcome = "SUCCEEDED",
        )
    }

    private suspend fun doExecuteInternal(
        args: CreateAuthorizationRequestArgs,
        applyDuring: (CreateAuthorizationRequestArgs) -> CreateAuthorizationRequestArgs,
    ): IdkResult<CreatedAuthorizationRequest, IdkError> {
        val rawArgs = applyDuring(args)
        val instanceId =
            try {
                Oid4vpSessionIdentity.normalize("instanceId", rawArgs.instanceId)
            } catch (e: IllegalArgumentException) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = e.message ?: "Invalid verifier instanceId"))
            }

        // When JAR signing is enabled the verifier self-identifies per OID4VP 1.0 §5.9.3
        // via a prefixed client_id (decentralized_identifier:..., x509_san_dns:..., or
        // x509_hash:...). §5.9.3 also forbids signing under the redirect_uri prefix, so
        // the caller-provided HTTPS client_id is not a valid signing identity and must
        // be replaced. client_metadata is KEPT — §5.9.3 requires it for DID bindings
        // ("All Verifier metadata other than the public key MUST be obtained from the
        // client_metadata parameter"), and the X.509 bindings say the same.
        //
        // No fallback: if signing is enabled and binding resolution fails, we surface
        // the error rather than emitting a request the wallet will reject.
        val processedArgs =
            if (requestObjectSigningConfig.enabled && !rawArgs.clientId.isOid4vpPrefixedClientId()) {
                val binding =
                    requestObjectSigningConfig.resolveSignerBinding()
                        ?: return Err(
                            IdkError.UNKNOWN_ERROR(
                                message =
                                    "Request-object signing is enabled but no signer binding is configured. " +
                                        "Set oid4vp.verifier.request-object.signing.mode to one of did:<method>, " +
                                        "x509_san_dns, or x509_hash — this determines the OID4VP §5.9.3 " +
                                        "Client Identifier Prefix and the JOSE header of the signed " +
                                        "Request Object (JAR / JWT-Secured Authorization Request, RFC 9101).",
                            ),
                        )
                log.info(
                    "Substituting verifier client_id '${rawArgs.clientId}' with signing binding " +
                        "'${binding.clientId}' (scheme=${binding.scheme})",
                )
                rawArgs.copy(
                    clientId = binding.clientId,
                    clientIdScheme = binding.scheme,
                )
            } else {
                rawArgs
            }

        log.debug("Creating OpenID4VP authorization request")

        // Validate required parameters
        val validationError = validateArgs(processedArgs)
        if (validationError != null) {
            return Err(validationError)
        }

        // Serialize DCQL query to JsonObject
        val dcqlQueryJson =
            serializeDcqlQuery(processedArgs.dcqlQuery)
                ?: return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message = "Failed to serialize DCQL query",
                    ),
                )

        // Determine redirect URI — per OID4VP spec, redirect_uri and response_uri are
        // mutually exclusive. For direct_post modes, only response_uri is used.
        val isDirectPost =
            processedArgs.responseMode == ResponseMode.DIRECT_POST ||
                processedArgs.responseMode == ResponseMode.DIRECT_POST_JWT
        val isDigitalCredentials =
            processedArgs.responseMode == ResponseMode.DC_API ||
                processedArgs.responseMode == ResponseMode.DC_API_JWT
        val redirectUri =
            if (isDigitalCredentials || (isDirectPost && processedArgs.responseUri != null)) {
                null // response_uri replaces redirect_uri for direct_post
            } else {
                processedArgs.redirectUri
                    ?: processedArgs.clientId // For redirect_uri scheme, client_id IS the redirect_uri
            }

        // Generate session ID for response correlation (returned to caller and stored in the authorization request as additional param).
        val sessionId = generateSessionId()

        // The effective state is what the wallet echoes back in the direct_post response.
        // When the caller provides a custom state, use that; otherwise default to sessionId.
        // This value is also used as the session's correlationId / KV store key so that
        // the direct_post endpoint can look up the session by the echoed state.
        val effectiveState = processedArgs.state ?: sessionId

        // A caller-selected state is also the persistence key. Never turn create into a blind
        // upsert that replaces another live request's nonce and DCQL query.
        val correlationIdExists = authorizationSessionStore.exists(effectiveState).getOrElse { return Err(it) }
        if (processedArgs.operationFingerprint == null &&
            (effectiveState.startsWith(AuthorizationSessionStore.CLAIMED_CORRELATION_PREFIX) ||
                effectiveState.startsWith(AuthorizationSessionStore.LEGACY_CLAIMED_CORRELATION_PREFIX))) {
            return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Reserved claimed-session correlation namespace"))
        }
        if (correlationIdExists && processedArgs.operationFingerprint == null) {
            return Err(
                IdkError.ALREADY_EXISTS_ERROR(
                    resource = "oid4vp authorization session:$effectiveState",
                    message = "Authorization session already exists: $effectiveState",
                ),
            )
        }

        // Build the authorization request using the type-safe builder
        val request =
            buildOid4vpAuthorizationRequest(
                clientId = processedArgs.clientId,
                redirectUri = redirectUri,
                responseType = "vp_token",
            ) {
                // Required parameters
                nonce(processedArgs.nonce)
                dcqlQuery(dcqlQueryJson)

                // Response mode and URI
                responseMode(processedArgs.responseMode)
                if (isDirectPost) {
                    processedArgs.responseUri?.let { responseUri(it) }
                }

                // OID4VP 1.0 Final §5.9.1 removed the `client_id_scheme` parameter: the prefix
                // is now part of the `client_id` itself (e.g. `decentralized_identifier:did:...`).
                // Emitting `client_id_scheme=decentralized_identifier` breaks credo-ts, whose
                // legacy enum (`zLegacyClientIdScheme`) accepts only `did` — it will reject
                // `decentralized_identifier` as an unknown legacy scheme and 400 the request.
                // We therefore only emit it for schemes whose values still match the legacy enum
                // and where the caller didn't already encode the prefix in client_id.
                val clientIdCarriesPrefix =
                    ClientIdScheme.entries.any { s -> s.prefix != null && processedArgs.clientId.startsWith(s.prefix + ":") }
                if (!isDigitalCredentials && !clientIdCarriesPrefix) {
                    processedArgs.clientIdScheme.prefix?.let { clientIdScheme(it) }
                }

                // State for request correlation (OID4VP 1.0 Section 5.1).
                // The wallet echoes state back in the direct_post response.
                if (!isDigitalCredentials) state(effectiveState)
                if (isDigitalCredentials) {
                    processedArgs.expectedOrigins?.let { origins ->
                        additionalParameter("expected_origins", JsonArray(origins.map { JsonPrimitive(it) }))
                    }
                }

                // Client metadata (embedded or by reference) per OID4VP §11.1.
                processedArgs.clientMetadata?.let { clientMetadata(it) }
                processedArgs.clientMetadataUri?.let { clientMetadataUri(it) }

                // OID4VP §5.10: GET (default per RFC 9101) vs POST for the JAR fetch. The
                // builder lands the value in additionalParameters; BuildAuthorizationRequestUriCommandImpl
                // then surfaces it as `&request_uri_method=…` on the outer OAuth2 URL — the
                // wallet needs to read this before fetching the JAR, so it MUST appear there
                // and not just inside the signed Request Object.
                if (!isDigitalCredentials) processedArgs.requestUriMethod?.let { requestUriMethod(it) }
            }

        log.info(
            "Created authorization request with client_id: ${processedArgs.clientId}, " +
                "response_mode: ${processedArgs.responseMode.value}",
        )
        // Full request payload for diagnostics (debug-gated). Includes client_id,
        // response_mode, response_uri, nonce, state, dcql_query, client_metadata, etc.
        log.debug("Authorization request (full): $request")

        // Persist an authorization session keyed by effectiveState (the wallet-echoed correlation key).
        val now = Clock.System.now().toEpochMilliseconds()
        val ttlSeconds = processedArgs.ttlSeconds ?: AuthorizationSessionStore.DEFAULT_TTL_SECONDS
        val expiresAt = authorizationSessionExpiresAt(now, ttlSeconds).getOrElse { return Err(it) }
        val session =
            AuthorizationSession(
                instanceId = instanceId,
                sessionId = sessionId,
                correlationId = effectiveState,
                queryId = processedArgs.dcqlQueryId,
                dcqlQuery = processedArgs.dcqlQuery,
                dcqlQueryId = processedArgs.dcqlQueryId,
                dcqlQueryVersion = processedArgs.dcqlQueryVersion,
                verifierId = processedArgs.verifierId,
                templateId = processedArgs.templateId,
                templateRevision = processedArgs.templateRevision,
                authorizationRequest = request,
                // Post-completion destination for the direct_post response body. It is NOT part of
                // the request the wallet fetches (redirect_uri and response_uri are mutually
                // exclusive there), so the session is the only place it can survive to response time.
                directPostResponseRedirectUri = processedArgs.directPostResponseRedirectUri,
                status = AuthorizationSessionStatus.AUTHORIZATION_REQUEST_CREATED,
                error = null,
                parsedResponse = null,
                validationResult = null,
                callback = null,
                boundInvitationToken = processedArgs.boundInvitationToken,
                postPresentationHookAllowList = processedArgs.postPresentationHookAllowList,
                credentialStatusPolicies = processedArgs.credentialStatusPolicies,
                createdAt = now,
                updatedAt = now,
                expiresAt = expiresAt,
            )

        val operationFingerprint = processedArgs.operationFingerprint
        val persisted = if (operationFingerprint != null) {
            authorizationSessionStore.createClaimedSession(session, operationFingerprint, ttlSeconds).getOrElse { return Err(it) }
        } else {
            authorizationSessionStore.put(effectiveState, session, ttlSeconds).getOrElse { return Err(it) }
            session
        }
        pendingHistorySession = persisted

        return Ok(
            CreatedAuthorizationRequest(
                request = persisted.authorizationRequest,
                sessionId = persisted.correlationId,
            ),
        )
    }

    /**
     * Validate CreateAuthorizationRequestArgs
     */
    private fun validateArgs(args: CreateAuthorizationRequestArgs): IdkError? {
        // Validate client_id
        if (args.clientId.isBlank()) {
            return IdkError.ILLEGAL_ARGUMENT_ERROR(
                message = "client_id is required",
            )
        }

        // Validate nonce (required for holder binding)
        if (args.nonce.isBlank()) {
            return IdkError.ILLEGAL_ARGUMENT_ERROR(
                message = "nonce is required for holder binding",
            )
        }

        // Validate nonce length (minimum characters per best practices)
        if (args.nonce.length < MIN_NONCE_LENGTH) {
            return IdkError.ILLEGAL_ARGUMENT_ERROR(
                message = "nonce must be at least 8 characters for security",
            )
        }

        // Validate response_uri is provided for direct_post modes
        if ((
                args.responseMode == ResponseMode.DIRECT_POST ||
                    args.responseMode == ResponseMode.DIRECT_POST_JWT
            ) &&
            args.responseUri.isNullOrBlank()
        ) {
            return IdkError.ILLEGAL_ARGUMENT_ERROR(
                message = "response_uri is required for ${args.responseMode.value} response mode",
            )
        }

        // Validate redirect_uri is provided for fragment/query modes
        if ((
                args.responseMode == ResponseMode.FRAGMENT ||
                    args.responseMode == ResponseMode.QUERY
            ) &&
            args.redirectUri.isNullOrBlank() &&
            args.clientIdScheme != ClientIdScheme.REDIRECT_URI
        ) {
            return IdkError.ILLEGAL_ARGUMENT_ERROR(
                message = "redirect_uri is required for ${args.responseMode.value} response mode",
            )
        }

        val dcqlValidation = validateDcqlQuery(args.dcqlQuery)
        if (dcqlValidation is Invalid) {
            return IdkError.ILLEGAL_ARGUMENT_ERROR(
                message =
                    "Invalid OpenID4VP 1.0 Final dcql_query: " +
                        dcqlValidation.errors.joinToString("; ") { "${it.path}: ${it.message}" },
            )
        }

        // Validate mutual exclusivity of client_metadata and client_metadata_uri
        if (args.clientMetadata != null && args.clientMetadataUri != null) {
            return IdkError.ILLEGAL_ARGUMENT_ERROR(
                message = "client_metadata and client_metadata_uri are mutually exclusive",
            )
        }

        // OID4VP §5.10: "Two case-sensitive valid values are defined in this specification:
        // `get` and `post`." Reject anything else loudly so a caller typo can't silently
        // produce a wallet-rejecting request.
        args.requestUriMethod?.let { m ->
            if (m != "get" && m != "post") {
                return IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message =
                        "Invalid request_uri_method '$m'. Per OID4VP §5.10 the only " +
                            "case-sensitive valid values are 'get' and 'post'.",
                )
            }
        }

        return null
    }

    /**
     * Serialize DCQL query to JsonObject
     */
    private fun serializeDcqlQuery(query: DcqlQuery): kotlinx.serialization.json.JsonObject? =
        try {
            Json.encodeToJsonElement(DcqlQuery.serializer(), query).jsonObject
        } catch (e: Exception) {
            log.error("Failed to serialize DCQL query: ${e.message}")
            null
        }

    /**
     * Generate a unique session ID (UUID v4) for response correlation.
     * Per Fides Universal OID4VP spec: "If not provided a random UUID will be assigned."
     */
    private fun generateSessionId(): String = Uuid.random().toString()

    /**
     * Whether [this] client_id already carries an OID4VP §5.9.3 prefix (e.g.
     * `decentralized_identifier:did:...`, `x509_san_dns:...`, `x509_hash:...`).
     * Prefix-carrying client_ids are left untouched; only bare HTTPS/redirect-uri
     * client_ids are replaced with the signing binding.
     */
    private fun String.isOid4vpPrefixedClientId(): Boolean = ClientIdScheme.entries.any { it.prefix != null && startsWith(it.prefix + ":") }

    private companion object {
        private const val MIN_NONCE_LENGTH = 8
    }
}
