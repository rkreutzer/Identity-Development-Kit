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

package com.sphereon.openid.oid4vp.universal.impl.command

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.encodeToBase64Url
import com.sphereon.crypto.core.generic.DigestAlg
import com.sphereon.crypto.core.generic.hash
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.service.TypedServiceCommandAdapter
import com.sphereon.core.events.SessionEventService
import com.sphereon.crypto.core.CoseJoseKeyMappingService
import com.sphereon.openid.oid4vp.verifier.federation.VerifierFederationMetadata
import com.sphereon.crypto.core.KeyInfo
import com.sphereon.crypto.core.KeyVisibility
import com.sphereon.crypto.core.jose.Jwk
import com.sphereon.crypto.core.jose.JwkSet
import com.sphereon.crypto.core.kms.ContentEncryptionAlgorithm
import com.sphereon.crypto.core.kms.KeyManagerService
import com.sphereon.crypto.core.kms.KmsProviderCapabilities
import com.sphereon.di.session.SessionScope
import com.sphereon.openid.oid4vc.common.QrCodeService
import com.sphereon.openid.oid4vp.common.ClientIdScheme
import com.sphereon.openid.oid4vp.common.ResponseMode
import com.sphereon.openid.oid4vp.dcql.store.DcqlQueryResolver
import com.sphereon.openid.oid4vp.universal.CreateAuthRequestServiceCommand
import com.sphereon.openid.oid4vp.universal.CreateAuthorizationRequestInput
import com.sphereon.openid.oid4vp.universal.CreateAuthorizationRequestOutput
import com.sphereon.openid.oid4vp.universal.AuthorizationRequestMethod
import com.sphereon.openid.oid4vp.universal.UniversalOid4vpConfigProvider
import com.sphereon.openid.oid4vp.universal.UniversalOid4vpEventTypes
import com.sphereon.openid.oid4vp.verifier.BuildAuthorizationRequestUriArgs
import com.sphereon.openid.oid4vp.verifier.CreateAuthorizationRequestArgs
import com.sphereon.openid.oid4vp.verifier.Oid4vpUriScheme
import com.sphereon.openid.oid4vp.verifier.Oid4vpVerifierService
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSessionCallbackConfig
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSessionStatus
import com.sphereon.openid.oid4vp.verifier.model.Oid4vpSessionIdentity
import com.sphereon.openid.oid4vp.verifier.config.ResponseEncryptionKeyConfig
import com.sphereon.openid.oid4vp.verifier.config.currentInstanceIdOrDefault
import com.sphereon.openid.oid4vp.verifier.requesturi.RequestObjectSigningConfig
import com.sphereon.openid.oid4vp.verifier.requesturi.RequestUriHandler
import com.sphereon.openid.oid4vp.verifier.store.AuthorizationSessionStore
import com.sphereon.openid.oid4vp.verifier.store.ClientMetadataConfigurationStore
import com.sphereon.openid.oid4vp.universal.impl.event.putSessionEventIdentity
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlin.random.Random

import dev.zacsweers.metro.ExposeImplBinding
import com.sphereon.openid.oid4vp.verifier.config.MutableOid4vpVerifierInstanceIdProvider
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

internal suspend fun <T> withRequestedVerifierInstance(
    provider: MutableOid4vpVerifierInstanceIdProvider,
    requested: String?,
    action: suspend () -> IdkResult<T, IdkError>,
): IdkResult<T, IdkError> {
    val previous = provider.currentInstanceId()
    if (requested == null) return action()
    val selected = try {
        Oid4vpSessionIdentity.normalize("verifierId", requested)
    } catch (e: IllegalArgumentException) {
        return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = e.message ?: "Invalid verifierId"))
    }
    if (previous != null && previous != selected) {
        return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "verifierId does not match the routed verifier instance"))
    }
    provider.setCurrentInstanceId(selected)
    return try {
        action()
    } finally {
        if (previous == null) provider.clearCurrentInstanceId() else provider.setCurrentInstanceId(previous)
    }
}
internal const val SUPPORTED_RESPONSE_TYPE: String = "vp_token"

internal fun claimedAuthorizationState(operationId: String): String =
    AuthorizationSessionStore.CLAIMED_CORRELATION_PREFIX + hash(operationId.encodeToByteArray(), DigestAlg.SHA256).encodeToBase64Url()

internal fun validateCreateAuthResponseType(responseType: String?): IdkError? {
    val requested = responseType?.takeIf { it.isNotBlank() } ?: return null
    return if (requested.equals(SUPPORTED_RESPONSE_TYPE, ignoreCase = true)) {
        null
    } else {
        IdkError.ILLEGAL_ARGUMENT_ERROR(
            message = "Unsupported response_type '$requested'. Supported: $SUPPORTED_RESPONSE_TYPE",
        )
    }
}

internal fun resolveSessionCorrelationId(
    correlationId: String?,
    state: String?,
    generateId: () -> String,
): IdkResult<String, IdkError> {
    val requestedCorrelationId = correlationId?.takeIf { it.isNotBlank() }
    val requestedState = state?.takeIf { it.isNotBlank() }
    if (requestedCorrelationId != null && requestedState != null && requestedCorrelationId != requestedState) {
        return Err(
            IdkError.ILLEGAL_ARGUMENT_ERROR(
                message = "correlation_id and state must match when both are provided",
            ),
        )
    }
    return Ok(requestedCorrelationId ?: requestedState ?: generateId())
}

internal fun com.sphereon.openid.oid4vp.verifier.model.AuthorizationSession.withUniversalResponseBehavior(
    callback: AuthorizationSessionCallbackConfig?,
    directPostResponseRedirectUri: String?,
) = copy(
    callback = callback,
    directPostResponseRedirectUri = directPostResponseRedirectUri,
)

/**
 * Typed service command implementation for creating authorization requests.
 *
 * POST /oid4vp/backend/auth/requests
 *
 * This implementation uses the Binary API v5 pattern with:
 * - Typed input: [CreateAuthorizationRequestInput] (JSON body)
 * - Typed output: [CreateAuthorizationRequestOutput]
 * - HTTP binding via [PublicApiCommand] on [CreateAuthRequestServiceCommand]
 *
 * The input is automatically deserialized from the request body by the BinaryCommandAdapter.
 * The output is automatically serialized to JSON.
 */
@Inject
@SingleIn(SessionScope::class)
@ExposeImplBinding
class CreateAuthRequestServiceCommandImpl(
    execution: SessionExecution,
    private val oid4vpVerifierService: Oid4vpVerifierService,
    private val dcqlQueryResolver: DcqlQueryResolver,
    private val clientMetadataConfigStore: ClientMetadataConfigurationStore,
    private val sessionEventService: SessionEventService,
    private val instanceIdProvider: MutableOid4vpVerifierInstanceIdProvider,
    private val qrCodeService: QrCodeService,
    private val configProvider: UniversalOid4vpConfigProvider,
    private val requestObjectSigningConfig: RequestObjectSigningConfig,
    private val requestUriHandler: RequestUriHandler,
    private val responseEncryptionKeyConfig: ResponseEncryptionKeyConfig,
    private val kms: KeyManagerService,
) : TypedServiceCommandAdapter<CreateAuthorizationRequestInput, CreateAuthorizationRequestOutput, IdkError>(
        commandId = CreateAuthRequestServiceCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<CreateAuthorizationRequestInput>(),
        outputTypeToken = typeToken<CreateAuthorizationRequestOutput>(),
    ),
    CreateAuthRequestServiceCommand {
    override val commandId: String get() = CreateAuthRequestServiceCommand.COMMAND_ID
    private val instanceMutationMutex = Mutex()

    override suspend fun doExecute(
        args: CreateAuthorizationRequestInput,
        applyDuring: (CreateAuthorizationRequestInput) -> CreateAuthorizationRequestInput,
    ): IdkResult<CreateAuthorizationRequestOutput, IdkError> {
        val input = applyDuring(args)
        return instanceMutationMutex.withLock {
            withRequestedVerifierInstance(instanceIdProvider, input.verifierId) {
                executeForInstance(input)
            }
        }
    }

    private suspend fun executeForInstance(input: CreateAuthorizationRequestInput): IdkResult<CreateAuthorizationRequestOutput, IdkError> {
        val instanceId =
            try {
                Oid4vpSessionIdentity.normalize(
                    "instanceId",
                    instanceIdProvider.currentInstanceIdOrDefault(),
                )
            } catch (e: IllegalArgumentException) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = e.message ?: "Invalid verifier instanceId"))
            }

        // 1. Validate input - must have either queryId or dcqlQuery
        val inputQueryId = input.queryId
        val inputDcqlQuery = input.dcqlQuery
        val inputClientMetadataId = input.clientMetadataId

        if (inputQueryId == null && inputDcqlQuery == null) {
            return Err(
                IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message = "Either query_id or dcql_query must be provided",
                ),
            )
        }

        // The verifier only builds `vp_token` requests today (id_token has no holder-side or
        // response-validation support here). Reject anything else rather than accept a value and
        // silently build a vp_token request.
        validateCreateAuthResponseType(input.responseType)?.let { return Err(it) }

        // 2. Resolve DCQL query (via the resolver SPI for a stored query_id, or inline)
        val resolvedQuery =
            if (inputQueryId != null) {
                dcqlQueryResolver.resolveForCreate(inputQueryId, input.verifierId).getOrElse { return Err(it) }
            } else {
                null
            }
        val dcqlQuery = resolvedQuery?.dcqlQuery ?: inputDcqlQuery!!

        // 3. Resolve client metadata (from config store or use default)
        val clientMetadataConfig =
            if (inputClientMetadataId != null) {
                clientMetadataConfigStore.getByClientMetadataId(inputClientMetadataId).getOrNull()
                    ?: return Err(
                        IdkError.NOT_FOUND_ERROR(
                            message = "Client metadata configuration not found: $inputClientMetadataId",
                        ),
                    )
            } else {
                // Use first available client metadata config as default
                val allConfigs = clientMetadataConfigStore.getAll().getOrNull()
                allConfigs?.values?.firstOrNull()
            }

        // Derive the session correlation id BEFORE resolving the JARM key, so the JWK we
        // publish in client_metadata can carry kid = correlationId. Per OID4VP §8.3
        // the wallet echoes the JWK's kid in the JWE header; the response endpoint then
        // uses JWE.kid → correlationId for a direct session lookup (no secondary index in
        // the session store needed).
        //
        // The response endpoint uses the wallet-echoed state as the session key. A caller may
        // supply either the Universal API correlation_id or the state extension, but distinct
        // values cannot both be represented without silently replacing one of them.
        val operationId = input.operationId
        if (operationId != null && (operationId.isBlank() || input.correlationId != null || input.state != null)) {
            return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Claimed verification requires a nonblank operation_id and server-derived correlation"))
        }
        val operationFingerprint = operationId?.let {
            hash(kotlinx.serialization.json.Json.encodeToString(CreateAuthorizationRequestInput.serializer(), input).encodeToByteArray(), DigestAlg.SHA256).encodeToBase64Url()
        }
        val correlationId = operationId?.let {
            claimedAuthorizationState(it)
        } ?: resolveSessionCorrelationId(input.correlationId, input.state) {
                ByteArray(16).also { Random.nextBytes(it) }.encodeToBase64Url()
            }.getOrElse { return Err(it) }

        // Resolve the requested client-identifier scheme first — when set, the signing
        // config returns a binding whose JOSE header / prefix match. Same KMS alias /
        // cert / key serves all schemes; only the client_id prefix and JOSE header switch.
        val derivedFromSigner =
            if (
                requestObjectSigningConfig.enabled &&
                (input.authorizationRequestMethod == AuthorizationRequestMethod.REQUEST_URI ||
                    input.authorizationRequestMethod == AuthorizationRequestMethod.DC_API)
            ) {
                requestObjectSigningConfig.resolveSignerBinding(input.clientIdScheme)?.clientId
            } else {
                null
            }
        val universalConfig = configProvider.getConfig()
        val configuredVerifierBaseUrl =
            universalConfig
                .externalBaseUrl
                ?.trimEnd('/')
                ?.takeIf { base -> base.startsWith("https://") || base.startsWith("http://") }
        // Source of truth for the verifier's client_id, in priority order:
        //   1. Explicit `input.clientId` from the request body.
        //   2. Stored ClientMetadataConfig.
        //   3. The signed-JAR signer binding (`x509_hash:<hash>`, `x509_san_dns:<dns>`,
        //      `decentralized_identifier:did:...`) — the same identifier the JAR will
        //      carry per OID4VP §5.9.3, so deriving here keeps the outer client_id
        //      consistent with the signed payload's `iss` and the JOSE header's `kid`/`x5c`.
        val clientId =
            input.clientId
                ?: clientMetadataConfig?.clientId
                ?: derivedFromSigner
                ?: configuredVerifierBaseUrl
                ?: return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message = "client_id must be provided or configured via verifier external-base-url or request-object signing",
                    ),
                )

        // OID4VP 1.0 §5.9.3 `openid_federation`: the wallet resolves this verifier's metadata from a Trust Chain.
        val federationSession = ClientIdScheme.fromClientId(clientId) == ClientIdScheme.OPENID_FEDERATION

        // 4. Generate nonce
        val nonce = generateNonce()

        // 5. Determine response URI: deployment config > derived default.
        // Note: prior code read ClientMetadata.baseMetadata.redirectUris as a fallback,
        // but OID4VP §11.1 client_metadata doesn't define `redirect_uris` — that's OAuth2
        // RFC 7591. response_uri sourcing belongs to verifier deployment configuration.
        val responseUri =
            input.responseUri
                ?: universalConfig.responseUri
                ?: if (federationSession) {
                    // The metadata lists this instance's Response URI; a prefixed client_id is no URL to derive it from.
                    configuredVerifierBaseUrl?.let(VerifierFederationMetadata::defaultResponseUri)
                        ?: return Err(
                            IdkError.ILLEGAL_ARGUMENT_ERROR(
                                message = "An openid_federation verifier needs a configured response-uri or external-base-url",
                            ),
                        )
                } else {
                    "$clientId/response"
                }

        // 6. Resolve client_id_scheme: explicit > detect from client_id prefix > default
        val resolvedScheme =
            input.clientIdScheme
                ?: ClientIdScheme.fromClientId(clientId)

        // 7. Create authorization request via existing verifier service.
        // Honour the caller's response_mode (default `direct_post`). HAIP requires
        // `direct_post.jwt` (encrypted response) — the input drives this; the verifier
        // doesn't gate on a profile flag because callers select it per-request.
        val resolvedResponseMode =
            input.responseMode?.takeIf { it.isNotBlank() }?.let { raw ->
                ResponseMode.entries.firstOrNull { it.value.equals(raw, ignoreCase = true) }
                    ?: return Err(
                        IdkError.ILLEGAL_ARGUMENT_ERROR(
                            message =
                                "Unknown response_mode '$raw'. Supported: " +
                                    ResponseMode.entries.joinToString(", ") { it.value },
                        ),
                    )
            } ?: ResponseMode.DIRECT_POST
        val digitalCredentialsRequest = input.authorizationRequestMethod == AuthorizationRequestMethod.DC_API
        if (digitalCredentialsRequest != (resolvedResponseMode == ResponseMode.DC_API_JWT)) {
            return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "dc_api authorization_request_method requires response_mode dc_api.jwt, and dc_api.jwt requires dc_api invocation"))
        }
        if (digitalCredentialsRequest) {
            if (!requestObjectSigningConfig.enabled) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Signed DC API requests require configured request-object signing"))
            }
            val expectedOrigins = input.expectedOrigins
            if (expectedOrigins == null || expectedOrigins.size != 1 || expectedOrigins.any { !it.matches(Regex("^https?://[^/?#@\\s]+$")) }) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Signed dc_api.jwt requests require exactly one browser origin in expected_origins"))
            }
            if (!input.requestUriMethod.isNullOrBlank() || input.directPostResponseRedirectUri != null) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "DC API requests cannot use request_uri_method or direct_post_response_redirect_uri"))
            }
        } else if (input.expectedOrigins != null) {
            return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "expected_origins is only valid for DC API requests"))
        }
        // For direct_post.jwt the wallet encrypts the response with the verifier's public key. That
        // key belongs to the verifier instance and is provisioned durably out of band: the server
        // resolves its name from its own binding for the active tenant and instance, publishes the
        // public half here, and performs the ECDH key agreement with the private half when the
        // response arrives. Nothing is minted on this path, and no alias or provider id from
        // configuration or from the request takes part in the selection.
        val jarmKey: JarmEncryptionKey? =
            if (resolvedResponseMode == ResponseMode.DIRECT_POST_JWT || resolvedResponseMode == ResponseMode.DC_API_JWT) {
                val encryptionKeyName =
                    responseEncryptionKeyConfig.resolveEncryptionKeyName(instanceId)
                        ?: return Err(
                            IdkError.UNKNOWN_ERROR(message = ResponseEncryptionKeyConfig.RESPONSE_ENCRYPTION_KEY_UNAVAILABLE),
                        )
                // PUBLIC: only the public half leaves the KMS. The private half never crosses this
                // process, and the resolved name is the sole handle the response endpoint uses.
                val publicKeyResult =
                    kms.getKeyResult(
                        KeyInfo<Nothing>(
                            alias = encryptionKeyName,
                            keyVisibility = KeyVisibility.PUBLIC,
                        ),
                    )
                if (publicKeyResult.isErr) {
                    return Err(IdkError.UNKNOWN_ERROR(message = ResponseEncryptionKeyConfig.RESPONSE_ENCRYPTION_KEY_UNAVAILABLE))
                }
                val publicKeyInfo =
                    publicKeyResult.value.key
                        ?: return Err(
                            IdkError.UNKNOWN_ERROR(message = ResponseEncryptionKeyConfig.RESPONSE_ENCRYPTION_KEY_UNAVAILABLE),
                        )
                val publicJwk = CoseJoseKeyMappingService.toJoseJwk(publicKeyInfo.key).toPublicKey()

                // Pull the capabilities of the provider the resolved key actually lives in, so the
                // metadata advertises only what the verifier can decrypt. Hardcoding alg/enc lists
                // here would drift away from what DecryptJweCommandImpl supports the moment a new
                // alg lands; capabilities-driven advertisement keeps the metadata honest.
                val capabilities =
                    resolveProviderCapabilities(publicKeyInfo.providerId)
                        ?: return Err(
                            IdkError.UNKNOWN_ERROR(message = ResponseEncryptionKeyConfig.RESPONSE_ENCRYPTION_KEY_UNAVAILABLE),
                        )

                JarmEncryptionKey(
                    publicJwk =
                        publicJwk.copy(
                            // OID4VP §8.3: the wallet echoes this kid in the JWE header. Normally it is the
                            // session's correlationId, so the response endpoint finds the session directly. Under
                            // `openid_federation:` the wallet encrypts to the key in the verifier's federation
                            // metadata instead, published under its thumbprint, and the endpoint finds the session
                            // through the encrypted `state`.
                            kid = if (federationSession) VerifierFederationMetadata.kid(publicJwk) else correlationId,
                            // Public-only payload: strip the private scalar even if the KMS
                            // returned the full key. Defensive — the JWK must never be
                            // emitted on the wire with `d`.
                            d = null,
                            // Mark for encryption use so wallets and proxies don't reuse it
                            // for signing. RFC 7517 §4.2.
                            use = "enc",
                            // Override KMS-set `alg` (ES256, signing) with the JWE key-agreement
                            // alg the wallet must use. HAIP §5 + OID4VP §8.3 require alg=ECDH-ES
                            // on the encryption JWK; without this the wallet's
                            // `VP1FinalEncryptVPResponse: Failed to derive symmetric key` fires.
                            alg = com.sphereon.crypto.core.jose.JwaAlgorithm.ECDH_ES,
                        ),
                    supportedEncs = capabilities.contentEncryptionAlgorithms.toList(),
                    supportsKeyAgreement = capabilities.supportsKeyAgreement(),
                )
            } else {
                null
            }

        // Build the OID4VP §11.1 client_metadata. Caller-supplied ClientMetadataConfig
        // wins; otherwise emit the spec-defined default (vp_formats_supported + jwks +
        // encrypted_response_enc_values_supported when encryption is in play).
        val effectiveClientMetadata =
            clientMetadataConfig?.clientMetadata ?: buildOid4vpClientMetadata(jarmKey)

        val createArgs =
            CreateAuthorizationRequestArgs(
                instanceId = instanceId,
                dcqlQuery = dcqlQuery,
                clientId = clientId,
                responseUri = responseUri,
                responseMode = resolvedResponseMode,
                expectedOrigins = input.expectedOrigins,
                nonce = nonce,
                // Use the pre-generated correlationId. CreateAuthorizationRequestCommandImpl
                // copies state → effectiveState (the AuthorizationSession.correlationId), so
                // store-by-correlationId == lookup-by-JWE.kid.
                state = correlationId,
                clientMetadata = effectiveClientMetadata,
                clientIdScheme = resolvedScheme,
                // OID4VP §5.10: surfaces as `&request_uri_method=…` on the outer OAuth2 URL.
                // Caller-supplied; we don't second-guess (verifier-impl validates the value).
                requestUriMethod = input.requestUriMethod?.takeIf { it.isNotBlank() },
                dcqlQueryId = resolvedQuery?.dcqlQueryId,
                dcqlQueryVersion = resolvedQuery?.version,
                verifierId = input.verifierId,
                templateId = input.templateId,
                // OID4VP §7.2 post-completion destination. Lands on the session, not in the
                // request object: for direct_post the wallet gets `response_uri` and the two
                // parameters are mutually exclusive on the wire.
                directPostResponseRedirectUri = input.directPostResponseRedirectUri?.takeIf { it.isNotBlank() },
                // Session lifetime is decided here, at creation, so the stored `expiresAt` and
                // the store's own TTL agree — a caller TTL must not depend on whether a callback
                // was configured.
                ttlSeconds = input.ttlSeconds,
                credentialStatusPolicies = input.credentialStatusPolicies,
                operationFingerprint = operationFingerprint,
                templateRevision = input.templateRevision,
            )

        val created =
            oid4vpVerifierService.createAuthorizationRequest(createArgs).getOrElse { error ->
                return Err(
                    IdkError.UNKNOWN_ERROR(
                        message = "Failed to create authorization request: ${error.message.defaultMessage}",
                    ),
                )
            }

        val sessionId =
            created.sessionId
                ?: return Err(IdkError.UNKNOWN_ERROR(message = "Session ID not generated"))

        var persistedSession =
            oid4vpVerifierService.authorizationSessionStore.getByCorrelationId(sessionId).getOrElse { return Err(it) }
                ?: return Err(
                    IdkError.UNKNOWN_ERROR(
                        message = "Created authorization session was not persisted: $sessionId",
                    ),
                )

        // 8. Update the session with the callback config when one was supplied.
        // `direct_post_response_redirect_uri` and the TTL already landed on the session at
        // creation (see createArgs above), which is what makes a caller TTL independent of
        // whether a callback was configured. Both are repeated here because `put` rewrites the
        // whole store entry and would otherwise drop the redirect and reset the expiry to the
        // store default.
        val inputCallback = input.callback
        val directPostResponseRedirectUri = input.directPostResponseRedirectUri?.takeIf { it.isNotBlank() }
        if (inputCallback != null || directPostResponseRedirectUri != null) {
            persistedSession =
                persistedSession.withUniversalResponseBehavior(
                    callback =
                        inputCallback?.let {
                            AuthorizationSessionCallbackConfig(
                                url = it.url,
                                statuses = it.statuses,
                                verifiedData = it.verifiedData,
                                secretRef = it.secretRef,
                                signing = it.signing,
                            )
                        },
                    directPostResponseRedirectUri = directPostResponseRedirectUri,
                )
            oid4vpVerifierService.authorizationSessionStore
                .put(
                    sessionId,
                    persistedSession,
                    input.ttlSeconds ?: AuthorizationSessionStore.DEFAULT_TTL_SECONDS,
                ).getOrElse { return Err(it) }
        }

        // 9. Build authorization request URI
        // Validate request_uri_base is an HTTP(S) URL — it controls the URL the wallet
        // fetches the signed JAR from, not the wallet-deeplink scheme. A custom scheme
        // (`oid4vp://`, `haip-vp://`) here would produce nonsense like
        // `oid4vp:/oid4vp/request-uri/<id>` that the wallet can't actually call.
        input.requestUriBase?.let { base ->
            val lower = base.lowercase()
            if (!lower.startsWith("http://") && !lower.startsWith("https://")) {
                return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message =
                            "request_uri_base must be an http(s) URL (got '$base'). " +
                                "The outer deeplink scheme is configured via 'wallet_uri_scheme'.",
                    ),
                )
            }
        }
        // walletUriScheme may be:
        //   - bare scheme name (`openid4vp`, `haip-vp`, `oid4vp`) → maps to Oid4vpUriScheme enum
        //   - full URL (`https://demo.certification.openid.net/.../authorize`) for web wallets,
        //     universal links, or app links → passed through as a deeplink prefix
        val rawWalletUri = input.walletUriScheme?.trim()?.takeIf { it.isNotEmpty() }
        val deeplinkPrefix: String?
        val outerScheme: Oid4vpUriScheme
        if (rawWalletUri == null) {
            deeplinkPrefix = null
            outerScheme = Oid4vpUriScheme.OPENID4VP
        } else if (rawWalletUri.contains("://") && !rawWalletUri.endsWith("://")) {
            // Full URL — web-wallet endpoint, universal link, or app link.
            deeplinkPrefix = rawWalletUri
            outerScheme = Oid4vpUriScheme.OPENID4VP // ignored when deeplinkPrefix is set
        } else {
            // Bare scheme name (with or without trailing `://`).
            val schemeName = rawWalletUri.removeSuffix("://")
            outerScheme = Oid4vpUriScheme.entries.firstOrNull { it.scheme.equals(schemeName, ignoreCase = true) }
                ?: return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message =
                            "Unknown wallet_uri_scheme '$schemeName'. Supported: " +
                                Oid4vpUriScheme.entries.joinToString(", ") { it.scheme } +
                                " — or pass a full URL (e.g. https://wallet.example.com/authorize) for a web-wallet endpoint.",
                    ),
                )
            deeplinkPrefix = null
        }
        if (input.authorizationRequestMethod != AuthorizationRequestMethod.REQUEST_URI && !input.requestUriMethod.isNullOrBlank()) {
            return Err(
                IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message = "request_uri_method is only valid when authorization_request_method is request_uri",
                ),
            )
        }
        val requestUri =
            if (digitalCredentialsRequest) null else oid4vpVerifierService
                .buildAuthorizationRequestUri(
                    BuildAuthorizationRequestUriArgs(
                        request = created.request,
                        scheme = outerScheme,
                        useRequestUri = input.authorizationRequestMethod == AuthorizationRequestMethod.REQUEST_URI,
                        requestUri =
                            if (input.authorizationRequestMethod == AuthorizationRequestMethod.REQUEST_URI) {
                                buildRequestUri(sessionId, input.requestUriBase)
                            } else {
                                null
                            },
                        deeplinkPrefix = deeplinkPrefix,
                    ),
                ).getOrElse { error ->
                    return Err(
                        IdkError.UNKNOWN_ERROR(
                            message = "Failed to build request URI: ${error.message.defaultMessage}",
                        ),
                    )
                }.value

        // A DC API verifier passes the signed Request Object directly to the browser API.
        // Reuse the same signer/binding that serves request_uri so x5c/kid identity cannot drift.
        val digitalCredentialsJar =
            if (digitalCredentialsRequest) {
                requestUriHandler.handleGet(buildRequestUri(sessionId, input.requestUriBase))
                    .getOrElse { return Err(it) }.signedJar
            } else null

        // 10. Generate QR code as data URI (only if qr_code options provided)
        val qrUri =
            input.qrCodeOptions?.takeUnless { digitalCredentialsRequest }?.let { qrOptions ->
                qrCodeService.generateDataUri(requireNotNull(requestUri), qrOptions)
            }

        // 11. Emit SESSION_CREATED event
        emitSessionCreatedEvent(persistedSession)

        // 12. Build response per Universal OID4VP spec
        val output =
            CreateAuthorizationRequestOutput(
                sessionId = persistedSession.sessionId,
                correlationId = sessionId,
                queryId = input.queryId,
                request = digitalCredentialsJar,
                requestUri = requestUri,
                statusUri = "/oid4vp/backend/auth/requests/$sessionId",
                qrUri = qrUri,
                verificationBinding = com.sphereon.openid.oid4vp.universal.VerificationSessionBinding(persistedSession.instanceId, persistedSession.templateId, persistedSession.templateRevision, persistedSession.dcqlQueryId, persistedSession.dcqlQueryVersion, persistedSession.createdAt, persistedSession.expiresAt),
            )

        return Ok(output)
    }

    /**
     * Generate a 32-byte (256-bit entropy) nonce, base64url-encoded without padding (43 chars).
     *
     * 64-char hex was producing the OIDF `CheckNonceMaximumLength` warning ("Nonce contains
     * in excess of 43 characters. This may introduce interoperability issues."). Same entropy,
     * tighter encoding — every char is in the RFC 3986 unreserved set, so the verifier-side
     * `CheckForInvalidCharsInNonce` still passes.
     */
    private fun generateNonce(): String {
        val bytes = ByteArray(32)
        Random.nextBytes(bytes)
        return bytes.encodeToBase64Url()
    }

    /**
     * Build the verifier's `client_metadata` per OID4VP 1.0 final. The shape is the spec's
     * narrow set: §11.1 `vp_formats_supported`, plus §5.1 / §8.3 `jwks` and
     * `encrypted_response_enc_values_supported` when encryption is requested.
     *
     * No JARM singular fields (not OID4VP-defined: alg lives on the JWK), no OAuth2
     * ClientRegistration fields (the wallet "MUST ignore unrecognized parameters", but
     * emitting them is non-canonical noise that confuses conformance and pollutes the JAR).
     */
    private fun buildOid4vpClientMetadata(jarmKey: JarmEncryptionKey?): com.sphereon.openid.oid4vp.common.ClientMetadata {
        val vpFormats = VerifierFederationMetadata.VP_FORMATS_SUPPORTED
        return com.sphereon.openid.oid4vp.common.ClientMetadata(
            jwks =
                jarmKey?.let {
                    com.sphereon.crypto.core.jose
                        .JwkSet(arrayOf(it.publicJwk))
                },
            vpFormatsSupported = vpFormats,
            // KMS-capability-driven enc advertisement. The JWE `alg` is conveyed via
            // jwks[*].alg (set on the public JWK above), per OID4VP §8.3 — there's no
            // top-level alg list in spec-correct client_metadata.
            encryptedResponseEncValuesSupported =
                jarmKey
                    ?.supportedEncs
                    ?.takeIf { it.isNotEmpty() }
                    ?.map { it.identifier },
        )
    }

    /**
     * Public half of the verifier's response-encryption key plus the KMS-advertised algorithms it
     * can actually decrypt under. Only [publicJwk] crosses the wire (in client_metadata.jwks); the
     * private half stays in the KMS and is reached again at decrypt time through the same
     * server-resolved key name, which is why no selector is carried anywhere.
     */
    private data class JarmEncryptionKey(
        val publicJwk: Jwk,
        val supportedEncs: List<ContentEncryptionAlgorithm>,
        val supportsKeyAgreement: Boolean,
    )

    /**
     * Look up the named provider's capabilities so client_metadata can advertise the
     * algorithms the verifier can actually consume. `getAllCapabilities` is the only
     * KMS API today that returns capabilities keyed by providerId; query and pick.
     */
    private suspend fun resolveProviderCapabilities(providerId: String): KmsProviderCapabilities? {
        val result = kms.getAllCapabilities()
        if (result.isErr) return null
        return result.value.capabilities[providerId]
    }

    private companion object {
        /** The only OAuth2 `response_type` this verifier builds requests for (OID4VP §5.1). */
        const val SUPPORTED_RESPONSE_TYPE: String = "vp_token"
    }


    /**
     * Build the request URI for an OID4VP authorization request.
     *
     * Resolution order for base URL:
     * 1. [inputRequestUriBase] from the API call (caller override)
     * 2. [UniversalOid4vpConfig.externalBaseUrl] from configuration
     * 3. Falls back to a relative path if neither is set
     */
    private fun buildRequestUri(
        correlationId: String,
        inputRequestUriBase: String?,
    ): String {
        val base = (inputRequestUriBase ?: configProvider.getConfig().externalBaseUrl)?.trimEnd('/')
        return if (base != null) {
            "$base/oid4vp/request-uri/$correlationId"
        } else {
            "/oid4vp/request-uri/$correlationId"
        }
    }

    private suspend fun emitSessionCreatedEvent(session: com.sphereon.openid.oid4vp.verifier.model.AuthorizationSession) {
        sessionEventService.emit(
                sessionEventService
                    .eventBuilder()
                    .type(UniversalOid4vpEventTypes.SESSION_CREATED)
                    .origin(CreateAuthRequestServiceCommand.COMMAND_ID)
                    .payload(
                        buildJsonObject {
                            put("correlationId", session.correlationId)
                            session.queryId?.let { put("queryId", it) }
                            putSessionEventIdentity(
                                protocolSessionId = session.sessionId,
                                instanceId = session.instanceId,
                                newState = AuthorizationSessionStatus.AUTHORIZATION_REQUEST_CREATED.name,
                                templateId = session.templateId,
                                creationSnapshot = buildJsonObject {
                                    put("correlationId", session.correlationId)
                                    session.queryId?.let { put("queryId", it) }
                                    session.templateId?.let { put("templateId", it) }
                                },
                                currentResult = buildJsonObject {
                                    put("correlationId", session.correlationId)
                                    session.queryId?.let { put("queryId", it) }
                                    put("sessionId", session.sessionId)
                                    put("status", AuthorizationSessionStatus.AUTHORIZATION_REQUEST_CREATED.name)
                                },
                            )
                        },
                    ).build(),
            )
    }
}
