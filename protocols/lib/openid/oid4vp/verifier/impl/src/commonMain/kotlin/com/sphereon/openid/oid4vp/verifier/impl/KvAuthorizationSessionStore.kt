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
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.encodeToHex
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.http.callback.CallbackSigningAlgorithm
import com.sphereon.core.api.log.AppLogManager
import com.sphereon.core.events.SessionEventService
import com.sphereon.data.store.kv.InMemoryKvStoreConfig
import com.sphereon.data.store.kv.KotlinxSerializationJsonKvCodec
import com.sphereon.data.store.kv.KvNamespace
import com.sphereon.data.store.kv.KvStore
import com.sphereon.data.store.kv.KvStoreVersioning
import com.sphereon.data.store.kv.KvVersionAppendResult
import com.sphereon.data.store.kv.KvStoreConfigBase
import com.sphereon.data.store.kv.KvStoreScopeBinding
import com.sphereon.data.store.kv.impl.KvStoreManager
import com.sphereon.data.store.kv.impl.KvStoreService
import com.sphereon.di.session.SessionScope
import com.sphereon.openid.oid4vp.common.ResponseMode
import com.sphereon.openid.oid4vp.common.VpToken
import com.sphereon.openid.oid4vp.common.buildOid4vpAuthorizationRequest
import com.sphereon.openid.oid4vp.common.store.StoreMetadata
import com.sphereon.openid.oid4vp.dcql.DcqlQuery
import com.sphereon.openid.oid4vp.dcql.store.DcqlQueryConfigurationStore
import com.sphereon.openid.oid4vp.universal.VerifiedDataOpts
import com.sphereon.openid.oid4vp.verifier.CredentialIssuerRef
import com.sphereon.openid.oid4vp.verifier.CredentialTrustValidation
import com.sphereon.openid.oid4vp.verifier.MatchedCredential
import com.sphereon.openid.oid4vp.verifier.claimValueToJson
import com.sphereon.openid.oid4vp.verifier.ParsedAuthorizationResponse
import com.sphereon.openid.oid4vp.verifier.CredentialValidationRejection
import com.sphereon.openid.oid4vp.verifier.ValidationResult
import com.sphereon.openid.oid4vp.verifier.callback.AuthorizationSessionCallbackDispatcher
import com.sphereon.openid.oid4vp.verifier.callback.AuthorizationSessionStatusResponseMapper
import com.sphereon.openid.oid4vp.verifier.Oid4vpVerifierSessionEventTypes
import com.sphereon.openid.oid4vp.verifier.impl.event.emitOid4vpSessionHistoryEvent
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSession
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSessionCallbackConfig
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSessionCreateArgs
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSessionError
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSessionStatus
import com.sphereon.openid.oid4vp.verifier.model.Oid4vpSessionIdentity
import com.sphereon.openid.oid4vp.verifier.store.AuthorizationSessionStore
import com.sphereon.statuslist.CredentialStatusPolicy
import dev.whyoleg.cryptography.random.CryptographyRandom
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.ExposeImplBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlin.time.Clock
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Duration.Companion.milliseconds

private const val RANDOM_BYTES_SIZE = 16

/**
 * KV-backed implementation of [AuthorizationSessionStore].
 *
 * Stored value is an internal, serializable envelope; public models are reconstructed on read.
 * TTL is enforced by the underlying KV store and mirrored in the stored `expiresAt`.
 */
@Inject
@SingleIn(SessionScope::class)
@ContributesBinding(SessionScope::class, binding = binding<AuthorizationSessionStore>())
@ExposeImplBinding
class KvAuthorizationSessionStore(
    private val kvStoreManager: KvStoreManager,
    private val kvStoreService: KvStoreService,
    private val dcqlQueryConfigurationStore: DcqlQueryConfigurationStore,
    private val callbackDispatcher: AuthorizationSessionCallbackDispatcher,
    private val statusResponseMapper: AuthorizationSessionStatusResponseMapper,
    appLogManager: AppLogManager,
    private val execution: SessionExecution,
    private val clock: Clock,
    private val eventService: SessionEventService? = null,
) : AuthorizationSessionStore {
    private val log = appLogManager.withTag("Oid4vpAuthorizationSessionStore")
    private val json = Json

    private val namespace =
        KvNamespace(
            name = "oid4vp.authorization_session",
            codec = KotlinxSerializationJsonKvCodec(json = json, serializer = AuthorizationSessionEntry.serializer()),
        )

    private val storeConfig: KvStoreConfigBase =
        InMemoryKvStoreConfig(
            id = "oid4vp.authorization_session",
            scopeBinding = KvStoreScopeBinding.TENANT,
        )

    private val kv: KvStore by lazy {
        kvStoreManager.createFromKvStoreConfig(resolveEffectiveStoreConfig(), execution)
    }

    /**
     * Resolve KV store configuration from the config abstraction (if present), otherwise fall back to [storeConfig].
     *
     * Important: this store requires [KvStoreScopeBinding.TENANT] semantics; configuration is validated to prevent
     * accidental scope changes that would break multi-tenant isolation guarantees.
     */
    private fun resolveEffectiveStoreConfig(): KvStoreConfigBase {
        val configured = runCatching { kvStoreService.getStoreConfig(storeConfig.id) }.getOrNull()
        val effective = configured ?: storeConfig
        require(effective.scopeBinding == storeConfig.scopeBinding) {
            "KV store '${storeConfig.id}' must use scopeBinding=${storeConfig.scopeBinding}, but was ${effective.scopeBinding}"
        }
        return effective
    }

    @Serializable
    internal data class AuthorizationSessionErrorEntry(
        val code: String,
        val message: String,
    ) {
        fun toPublic(): AuthorizationSessionError = AuthorizationSessionError(code = code, message = message)
    }

    @Serializable
    internal data class AuthorizationSessionCallbackEntry(
        val url: String,
        /**
         * Empty means "all transitions".
         */
        val statuses: List<String> = emptyList(),
        /** Absent on sessions stored before callback modes were persisted, which means no verified data. */
        val verifiedData: VerifiedDataOpts? = null,
        val secretRef: String? = null,
        val signing: String? = null,
    ) {
        fun toPublic(): AuthorizationSessionCallbackConfig =
            AuthorizationSessionCallbackConfig(
                url = url,
                statuses = statuses.mapNotNull { name -> AuthorizationSessionStatus.entries.firstOrNull { it.name == name } },
                verifiedData = verifiedData,
                secretRef = secretRef,
                signing = signing?.let { name -> CallbackSigningAlgorithm.entries.firstOrNull { it.name == name } },
            )

        companion object {
            fun fromPublic(config: AuthorizationSessionCallbackConfig): AuthorizationSessionCallbackEntry =
                AuthorizationSessionCallbackEntry(
                    url = config.url,
                    statuses = config.statuses.map(AuthorizationSessionStatus::name),
                    verifiedData = config.verifiedData,
                    secretRef = config.secretRef,
                    signing = config.signing?.name,
                )
        }
    }

    @Serializable
    internal data class ParsedAuthorizationResponseEntry(
        val rawVpToken: String,
        val state: String? = null,
        val jarmMode: String? = null,
        val jarmIssuer: String? = null,
    ) {
        fun toPublic(): ParsedAuthorizationResponse {
            val vpToken =
                KvAuthorizationSessionStore.parseVpToken(rawVpToken)
                    ?: throw IllegalArgumentException("Invalid vp_token format")
            val jarmModeEnum =
                jarmMode?.let {
                    try {
                        com.sphereon.oauth2.common.jarm.JarmMode
                            .valueOf(it)
                    } catch (_: Exception) {
                        // Ignored: unrecognized JARM mode value
                        null
                    }
                }
            return ParsedAuthorizationResponse(
                vpToken = vpToken,
                state = state,
                rawVpToken = rawVpToken,
                jarmMode = jarmModeEnum,
                jarmIssuer = jarmIssuer,
            )
        }
    }

    @Serializable
    internal data class MatchedCredentialEntry(
        val credentialQueryId: String,
        val credentialFormat: String,
        val presentationFormat: String? = null,
        val presentation: String,
        val disclosedClaims: Map<String, JsonElement> = emptyMap(),
        val issuer: CredentialIssuerRef? = null,
        val trust: CredentialTrustValidation? = null,
        val verificationEvidence: com.sphereon.openid.oid4vp.verifier.VerifiedCredentialEvidence? = null,
        /** The digital credential type reported as Universal OID4VP VerifiedClaimsValue.type; absent in older entries. */
        val credentialType: String? = null,
    ) {
        fun toPublic(): MatchedCredential =
            MatchedCredential(
                credentialQueryId = credentialQueryId,
                credentialFormat = requireNotNull(com.sphereon.openid.oid4vc.common.CredentialFormat.fromValue(credentialFormat)),
                presentationFormat = presentationFormat?.let { requireNotNull(com.sphereon.openid.oid4vc.common.PresentationFormat.fromValue(it)) },
                presentation = presentation,
                disclosedClaims = disclosedClaims.toClaimValues(),
                issuer = issuer,
                trust = trust,
                verificationEvidence = verificationEvidence,
                credentialType = credentialType,
            )

        companion object {
            fun fromPublic(matched: MatchedCredential): MatchedCredentialEntry =
                MatchedCredentialEntry(
                    credentialQueryId = matched.credentialQueryId,
                    credentialFormat = matched.credentialFormat.value,
                    presentationFormat = matched.presentationFormat?.value,
                    presentation = matched.presentation,
                    issuer = matched.issuer,
                    trust = matched.trust,
                    verificationEvidence = matched.verificationEvidence,
                    credentialType = matched.credentialType,
                    disclosedClaims = matched.disclosedClaims.mapValues { (_, value) -> claimValueToJson(value) },
                )
        }
    }

    @Serializable
    internal data class ValidationResultEntry(
        val valid: Boolean,
        val matchedCredentials: List<MatchedCredentialEntry> = emptyList(),
        val errors: List<String> = emptyList(),
        /**
         * Credentials discarded on credential-status grounds. Defaulted so that sessions written
         * before rejections existed still decode: their stored JSON carries no `rejections` key.
         */
        val rejections: List<CredentialValidationRejection> = emptyList(),
    ) {
        fun toPublic(): ValidationResult =
            ValidationResult(
                valid = valid,
                matchedCredentials = matchedCredentials.map { it.toPublic() },
                errors = errors,
                rejections = rejections,
            )
    }

    @Serializable
    internal data class AuthorizationSessionEntry(
        val instanceId: String,
        val sessionId: String,
        val correlationId: String,
        val queryId: String? = null,
        val dcqlQuery: DcqlQuery,
        val dcqlQueryId: String? = null,
        val dcqlQueryVersion: Int? = null,
        val verifierId: String? = null,
        val templateId: String? = null,
        val authorizationRequestJson: JsonObject,
        val status: String,
        val error: AuthorizationSessionErrorEntry? = null,
        val parsedResponse: ParsedAuthorizationResponseEntry? = null,
        val validationResult: ValidationResultEntry? = null,
        val callback: AuthorizationSessionCallbackEntry? = null,
        // OID4VP §7.2 post-completion destination. Stored beside the request rather than inside
        // it: the request object cannot carry `redirect_uri` for the direct_post modes.
        val directPostResponseRedirectUri: String? = null,
        val boundInvitationToken: String? = null,
        val postPresentationHookAllowList: List<String>? = null,
        val credentialStatusPolicies: Map<String, CredentialStatusPolicy>? = null,
        val createdAt: Long,
        val updatedAt: Long,
        val expiresAt: Long,
        val claimFingerprint: String? = null,
        val templateRevision: String? = null,
    ) {
        fun toPublic(json: Json): AuthorizationSession {
            val authorizationRequest =
                json.decodeFromJsonElement(
                    com.sphereon.oauth2.common.model.AuthorizationRequest
                        .serializer(),
                    authorizationRequestJson,
                )

            val statusEnum =
                AuthorizationSessionStatus.entries.firstOrNull { it.name == status }
                    ?: AuthorizationSessionStatus.ERROR

            return AuthorizationSession(
                instanceId = instanceId,
                sessionId = sessionId,
                correlationId = correlationId,
                queryId = queryId,
                dcqlQuery = dcqlQuery,
                dcqlQueryId = dcqlQueryId,
                dcqlQueryVersion = dcqlQueryVersion,
                verifierId = verifierId,
                templateId = templateId,
                templateRevision = templateRevision,
                authorizationRequest = authorizationRequest,
                status = statusEnum,
                error = error?.toPublic(),
                parsedResponse = parsedResponse?.toPublic(),
                validationResult = validationResult?.toPublic(),
                callback = callback?.toPublic(),
                directPostResponseRedirectUri = directPostResponseRedirectUri,
                boundInvitationToken = boundInvitationToken,
                postPresentationHookAllowList = postPresentationHookAllowList,
                credentialStatusPolicies = credentialStatusPolicies,
                createdAt = createdAt,
                updatedAt = updatedAt,
                expiresAt = expiresAt,
            )
        }
    }

    override suspend fun createSession(
        correlationId: String?,
        args: AuthorizationSessionCreateArgs,
        ttlSeconds: Long,
    ): IdkResult<AuthorizationSession, IdkError> {
        val instanceId =
            try {
                Oid4vpSessionIdentity.normalize("instanceId", args.instanceId)
            } catch (e: IllegalArgumentException) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = e.message ?: "Invalid verifier instanceId"))
            }
        val now = clock.now().toEpochMilliseconds()
        val effectiveCorrelationId = correlationId ?: generateSecureId()
        if (isClaimed(effectiveCorrelationId)) return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Reserved claimed-session correlation namespace"))
        val expiresAt = authorizationSessionExpiresAt(now, ttlSeconds).getOrElse { return Err(it) }
        val alreadyExists = kv.exists(namespace, effectiveCorrelationId).getOrElse { return Err(it) }
        if (alreadyExists) {
            return Err(
                IdkError.ALREADY_EXISTS_ERROR(
                    resource = "oid4vp authorization session:$effectiveCorrelationId",
                    message = "Authorization session already exists: $effectiveCorrelationId",
                ),
            )
        }

        val dcqlQuery = resolveDcqlQuery(args).getOrElse { return Err(it) }

        val authorizationRequestJson = buildAuthorizationRequestJson(args, dcqlQuery).getOrElse { return Err(it) }

        val sessionId = generateSecureId()
        val entry =
            AuthorizationSessionEntry(
                instanceId = instanceId,
                sessionId = sessionId,
                correlationId = effectiveCorrelationId,
                queryId = args.queryId,
                dcqlQuery = dcqlQuery,
                verifierId = args.verifierId,
                authorizationRequestJson = authorizationRequestJson,
                status = AuthorizationSessionStatus.AUTHORIZATION_REQUEST_CREATED.name,
                error = null,
                parsedResponse = null,
                validationResult = null,
                callback = args.callback?.let(AuthorizationSessionCallbackEntry::fromPublic),
                createdAt = now,
                updatedAt = now,
                expiresAt = expiresAt,
            )

        return kv
            .put(namespace, effectiveCorrelationId, entry, ttlSeconds.seconds)
            .map {
                val created = entry.toPublic(json)
                dispatchIfConfigured(created)
                created
            }.mapError { e ->
                IdkError.fromString(message = "Failed to create authorization session: ${e.message}", exception = IllegalStateException(e.toString()), code = "OID4VP_AUTH_SESSION_STORE_ERROR")
            }
    }

    override suspend fun getByCorrelationId(correlationId: String): IdkResult<AuthorizationSession?, IdkError> = get(correlationId)

    override suspend fun updateStatus(
        correlationId: String,
        status: AuthorizationSessionStatus,
        error: AuthorizationSessionError?,
    ): IdkResult<AuthorizationSession, IdkError> =
        update(correlationId) { existing, now ->
            val updatedError = error?.let { AuthorizationSessionErrorEntry(code = it.code, message = it.message) } ?: existing.error
            existing.copy(
                status = status.name,
                error = updatedError,
                updatedAt = now,
            )
        }

    override suspend fun storeResponse(
        correlationId: String,
        parsedResponse: ParsedAuthorizationResponse,
    ): IdkResult<AuthorizationSession, IdkError> =
        update(correlationId) { existing, now ->
            existing.copy(
                status = AuthorizationSessionStatus.AUTHORIZATION_RESPONSE_RECEIVED.name,
                parsedResponse =
                    ParsedAuthorizationResponseEntry(
                        rawVpToken = parsedResponse.rawVpToken,
                        state = parsedResponse.state,
                        jarmMode = parsedResponse.jarmMode?.name,
                        jarmIssuer = parsedResponse.jarmIssuer,
                    ),
                updatedAt = now,
            )
        }

    override suspend fun storeValidationResult(
        correlationId: String,
        validationResult: ValidationResult,
    ): IdkResult<AuthorizationSession, IdkError> =
        update(correlationId, dispatch = true) { existing, now ->
            validationEntry(existing, now, validationResult)
        }

    override suspend fun storeValidationResultDeferred(
        correlationId: String,
        validationResult: ValidationResult,
    ): IdkResult<AuthorizationSession, IdkError> =
        update(correlationId, dispatch = false) { existing, now ->
            validationEntry(existing, now, validationResult)
        }

    override suspend fun dispatchDeferredValidation(
        correlationId: String,
        previous: AuthorizationSession?,
    ): IdkResult<Unit, IdkError> {
        val current = get(correlationId).getOrElse { return Err(it) } ?: return Ok(Unit)
        emitStatusTransition(previous ?: current, current)
        dispatchIfConfigured(current)
        return Ok(Unit)
    }

    private fun validationEntry(
        existing: AuthorizationSessionEntry,
        now: Long,
        validationResult: ValidationResult,
    ): AuthorizationSessionEntry {
        val nextStatus =
            if (validationResult.valid) {
                AuthorizationSessionStatus.AUTHORIZATION_RESPONSE_VERIFIED
            } else {
                AuthorizationSessionStatus.ERROR
            }
        val nextError =
            if (!validationResult.valid && validationResult.errors.isNotEmpty()) {
                AuthorizationSessionErrorEntry(code = "validation_failed", message = validationResult.errors.joinToString("; "))
            } else {
                existing.error
            }
        return existing.copy(
            status = nextStatus.name,
            error = nextError,
            validationResult =
                ValidationResultEntry(
                    valid = validationResult.valid,
                    matchedCredentials = validationResult.matchedCredentials.map { MatchedCredentialEntry.fromPublic(it) },
                    errors = validationResult.errors,
                    rejections = validationResult.rejections,
                ),
            updatedAt = now,
        )
    }

    override suspend fun getForRequestUri(
        correlationId: String,
        markRetrieved: Boolean,
    ): IdkResult<AuthorizationSession?, IdkError> {
        val now = clock.now().toEpochMilliseconds()
        val existing =
            readEntry(correlationId).getOrElse { e ->
                return Err(
                    IdkError.fromString(
                        message = "Failed to read authorization session: ${e.message}",
                        exception = IllegalStateException(e.toString()),
                        code = "OID4VP_AUTH_SESSION_STORE_ERROR",
                    ),
                )
            } ?: return Ok(null)

        if (existing.expiresAt <= now) {
            kv.delete(namespace, correlationId)
            return Ok(null)
        }

        if (existing.status != AuthorizationSessionStatus.AUTHORIZATION_REQUEST_CREATED.name) {
            return Ok(null)
        }

        if (!markRetrieved) {
            return Ok(existing.toPublic(json))
        }

        return update(correlationId) { entry, updatedNow ->
            entry.copy(
                status = AuthorizationSessionStatus.AUTHORIZATION_REQUEST_RETRIEVED.name,
                updatedAt = updatedNow,
            )
        }.map { it }
    }

    override suspend fun put(
        key: String,
        value: AuthorizationSession,
        ttlSeconds: Long,
    ): IdkResult<StoreMetadata, IdkError> {
        val now = clock.now().toEpochMilliseconds()
        val expiresAt = authorizationSessionExpiresAt(now, ttlSeconds).getOrElse { return Err(it) }

        if (isClaimed(key)) return updateClaimedSnapshot(key, value)

        val entry = toEntry(value, now, expiresAt)
        return kv
            .put(namespace, key, entry, ttlSeconds.seconds)
            .map { putResult ->
                dispatchIfConfigured(entry.toPublic(json))
                StoreMetadata(createdAt = putResult.metadata.createdAtEpochMillis, expiresAt = putResult.metadata.expiresAtEpochMillis)
            }.mapError { e ->
                IdkError.fromString(message = "Failed to put authorization session: ${e.message}", exception = IllegalStateException(e.toString()), code = "OID4VP_AUTH_SESSION_STORE_ERROR")
            }
    }

    private fun toEntry(value: AuthorizationSession, now: Long, expiresAt: Long): AuthorizationSessionEntry {

        val authorizationRequestJson =
            json
                .encodeToJsonElement(
                    com.sphereon.oauth2.common.model.AuthorizationRequest
                        .serializer(),
                    value.authorizationRequest,
                ).jsonObject

        val entry =
            AuthorizationSessionEntry(
                instanceId = value.instanceId,
                sessionId = value.sessionId,
                correlationId = value.correlationId,
                queryId = value.queryId,
                dcqlQuery = value.dcqlQuery,
                dcqlQueryId = value.dcqlQueryId,
                dcqlQueryVersion = value.dcqlQueryVersion,
                verifierId = value.verifierId,
                templateId = value.templateId,
                templateRevision = value.templateRevision,
                authorizationRequestJson = authorizationRequestJson,
                status = value.status.name,
                error = value.error?.let { AuthorizationSessionErrorEntry(code = it.code, message = it.message) },
                parsedResponse =
                    value.parsedResponse?.let {
                        ParsedAuthorizationResponseEntry(
                            rawVpToken = it.rawVpToken,
                            state = it.state,
                            jarmMode = it.jarmMode?.name,
                            jarmIssuer = it.jarmIssuer,
                        )
                    },
                validationResult =
                    value.validationResult?.let {
                        ValidationResultEntry(
                            valid = it.valid,
                            matchedCredentials = it.matchedCredentials.map(MatchedCredentialEntry::fromPublic),
                            errors = it.errors,
                        )
                    },
                callback = value.callback?.let(AuthorizationSessionCallbackEntry::fromPublic),
                directPostResponseRedirectUri = value.directPostResponseRedirectUri,
                boundInvitationToken = value.boundInvitationToken,
                postPresentationHookAllowList = value.postPresentationHookAllowList,
                credentialStatusPolicies = value.credentialStatusPolicies,
                createdAt = value.createdAt,
                updatedAt = now,
                expiresAt = expiresAt,
            )

        return entry
    }

    override suspend fun get(key: String): IdkResult<AuthorizationSession?, IdkError> =
        readEntry(key).map { it?.toPublic(json) }.mapError { e ->
            IdkError.fromString(
                message = "Failed to read authorization session: ${e.message}",
                exception = IllegalStateException(e.toString()),
                code = "OID4VP_AUTH_SESSION_STORE_ERROR",
            )
        }

    override suspend fun getEntry(key: String): IdkResult<com.sphereon.openid.oid4vp.common.store.StoredEntry<AuthorizationSession>?, IdkError> {
        if (isClaimed(key)) return readEntry(key).map { entry -> entry?.let {
            com.sphereon.openid.oid4vp.common.store.StoredEntry(it.toPublic(json), it.createdAt, it.expiresAt)
        } }
        return kv
            .getEntry(namespace, key)
            .map { entry ->
                entry?.let {
                    com.sphereon.openid.oid4vp.common.store.StoredEntry(
                        value = it.value.toPublic(json),
                        createdAt = it.metadata.createdAtEpochMillis,
                        expiresAt = it.metadata.expiresAtEpochMillis,
                    )
                }
            }.mapError { e ->
                IdkError.fromString(
                    message = "Failed to read authorization session entry: ${e.message}",
                    exception = IllegalStateException(e.toString()),
                    code = "OID4VP_AUTH_SESSION_STORE_ERROR",
                )
            }
    }

    override suspend fun delete(key: String): IdkResult<Boolean, IdkError> =
        if (isClaimed(key)) Err(IdkError.INVALID_STATE(message = "Claimed verification history cannot be deleted through mutable session API"))
        else kv.delete(namespace, key).mapError { e ->
            IdkError.fromString(message = "Failed to delete authorization session: ${e.message}", exception = IllegalStateException(e.toString()), code = "OID4VP_AUTH_SESSION_STORE_ERROR")
        }

    override suspend fun exists(key: String): IdkResult<Boolean, IdkError> =
        readEntry(key).map { it != null }.mapError { e ->
            IdkError.fromString(message = "Failed to check authorization session existence: ${e.message}", exception = IllegalStateException(e.toString()), code = "OID4VP_AUTH_SESSION_STORE_ERROR")
        }

    override suspend fun touch(
        key: String,
        ttlSeconds: Long,
    ): IdkResult<Boolean, IdkError> {
        if (isClaimed(key)) return Err(IdkError.INVALID_STATE(message = "Claimed verification expiry is immutable"))
        authorizationSessionExpiresAt(clock.now().toEpochMilliseconds(), ttlSeconds).getOrElse { return Err(it) }
        return kv.touch(namespace, key, ttlSeconds.seconds).mapError { e ->
            IdkError.fromString(message = "Failed to touch authorization session: ${e.message}", exception = IllegalStateException(e.toString()), code = "OID4VP_AUTH_SESSION_STORE_ERROR")
        }
    }

    override suspend fun cleanupExpired(): IdkResult<Int, IdkError> =
        kv.cleanupExpired(namespace).mapError { e ->
            IdkError.fromString(message = "Failed to cleanup expired authorization sessions: ${e.message}", exception = IllegalStateException(e.toString()), code = "OID4VP_AUTH_SESSION_STORE_ERROR")
        }

    private suspend fun resolveDcqlQuery(args: AuthorizationSessionCreateArgs): IdkResult<DcqlQuery, IdkError> {
        args.dcqlQuery?.let { return Ok(it) }
        val queryId =
            args.queryId
                ?: return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Either dcqlQuery or queryId must be provided"))

        val config =
            dcqlQueryConfigurationStore.getByQueryId(queryId).getOrElse { return Err(it) }
                ?: return Err(IdkError.NOT_FOUND_ERROR(resource = "dcqlQueryConfiguration:$queryId", message = "DCQL query configuration not found: $queryId"))

        if (!config.enabled) {
            return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "DCQL query configuration is disabled: $queryId"))
        }
        return Ok(config.dcqlQuery)
    }

    private fun buildAuthorizationRequestJson(
        args: AuthorizationSessionCreateArgs,
        dcqlQuery: DcqlQuery,
    ): IdkResult<JsonObject, IdkError> {
        val redirectUri = args.redirectUri ?: args.responseUri ?: args.clientId

        val dcqlQueryJson =
            try {
                Json.encodeToJsonElement(DcqlQuery.serializer(), dcqlQuery).jsonObject
            } catch (expected: Exception) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Failed to serialize DCQL query", throwable = expected))
            }

        val request =
            buildOid4vpAuthorizationRequest(
                clientId = args.clientId,
                redirectUri = redirectUri,
                responseType = "vp_token",
            ) {
                nonce(args.nonce)
                dcqlQuery(dcqlQueryJson)

                responseMode(args.responseMode)
                if (args.responseMode == ResponseMode.DIRECT_POST || args.responseMode == ResponseMode.DIRECT_POST_JWT) {
                    args.responseUri?.let { responseUri(it) }
                }

                args.state?.let { state(it) }
            }

        return Ok(
            json
                .encodeToJsonElement(
                    com.sphereon.oauth2.common.model.AuthorizationRequest
                        .serializer(),
                    request,
                ).jsonObject,
        )
    }

    private fun isClaimed(key: String) = key.startsWith(AuthorizationSessionStore.CLAIMED_CORRELATION_PREFIX) ||
        key.startsWith(AuthorizationSessionStore.LEGACY_CLAIMED_CORRELATION_PREFIX)

    // Keep the original durable key across public state encodings. Both forms must
    // contend on the same append-if-absent operation, including during rolling upgrades.
    private fun claimedStorageKey(key: String): String =
        if (key.startsWith(AuthorizationSessionStore.CLAIMED_CORRELATION_PREFIX)) {
            AuthorizationSessionStore.LEGACY_CLAIMED_CORRELATION_PREFIX +
                key.removePrefix(AuthorizationSessionStore.CLAIMED_CORRELATION_PREFIX)
        } else key

    private fun comparableClaimRequest(entry: AuthorizationSessionEntry): Map<String, JsonElement> =
        entry.authorizationRequestJson.filterKeys { it != "nonce" }.mapValues { (name, value) ->
            when {
                name == "state" && value is JsonPrimitive && value.isString -> JsonPrimitive(claimedStorageKey(value.content))
                name == "client_metadata" && value is JsonObject -> comparableClaimMetadata(value, entry.correlationId)
                else -> value
            }
        }

    private fun comparableClaimMetadata(metadata: JsonObject, correlationId: String): JsonObject {
        val jwks = metadata["jwks"] as? JsonObject ?: return metadata
        val keys = jwks["keys"] as? JsonArray ?: return metadata
        val comparableKeys = keys.map { value ->
            val key = value as? JsonObject
            // Only the encryption kid derived from this exact correlation changes with
            // the state encoding. Keep key material, capabilities and other kids pinned.
            if (key != null && key["kid"] == JsonPrimitive(correlationId) && key["use"] == JsonPrimitive("enc")) {
                JsonObject(key + ("kid" to JsonPrimitive(claimedStorageKey(correlationId))))
            } else value
        }
        return JsonObject(metadata + ("jwks" to JsonObject(jwks + ("keys" to JsonArray(comparableKeys)))))
    }

    private fun durableVersioning(): IdkResult<KvStoreVersioning, IdkError> {
        val config = resolveEffectiveStoreConfig()
        if (!config.enabled || config.backendId == com.sphereon.data.store.kv.KvStoreBackends.MEMORY) return Err(
            IdkError.INVALID_STATE(message = "Claimed verification requires a configured persistent tenant session store"),
        )
        return (kv as? KvStoreVersioning)?.let { Ok(it) }
            ?: Err(IdkError.INVALID_STATE(message = "Claimed verification requires atomic KV versioning"))
    }

    private suspend fun readEntry(key: String): IdkResult<AuthorizationSessionEntry?, IdkError> {
        if (!isClaimed(key)) return kv.get(namespace, key)
        val store = durableVersioning().getOrElse { return Err(it) }
        return store.getHead(namespace, claimedStorageKey(key)).map { it?.value }
    }

    override suspend fun createClaimedSession(
        session: AuthorizationSession,
        fingerprint: String,
        ttlSeconds: Long,
    ): IdkResult<AuthorizationSession, IdkError> {
        if (!isClaimed(session.correlationId) || fingerprint.isBlank() ||
            session.status != AuthorizationSessionStatus.AUTHORIZATION_REQUEST_CREATED ||
            session.validationResult != null || session.parsedResponse != null
        ) return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Invalid claimed verification request"))
        val store = durableVersioning().getOrElse { return Err(it) }
        val now = clock.now().toEpochMilliseconds()
        val expires = authorizationSessionExpiresAt(now, ttlSeconds).getOrElse { return Err(it) }
        val entry = toEntry(session, now, expires).copy(claimFingerprint = fingerprint)
        return when (val result = store.append(namespace, claimedStorageKey(session.correlationId), null, entry, ttlSeconds.seconds).getOrElse { return Err(it) }) {
            is KvVersionAppendResult.Applied -> Ok(result.entry.value.toPublic(json))
            is KvVersionAppendResult.Conflict -> {
                val original = result.currentHead?.value
                if (original == null || original.claimFingerprint != fingerprint || original.instanceId != entry.instanceId ||
                    original.dcqlQuery != entry.dcqlQuery || original.dcqlQueryId != entry.dcqlQueryId ||
                    original.dcqlQueryVersion != entry.dcqlQueryVersion || original.templateId != entry.templateId || original.templateRevision != entry.templateRevision ||
                    original.credentialStatusPolicies != entry.credentialStatusPolicies ||
                    comparableClaimRequest(original) != comparableClaimRequest(entry)
                ) Err(IdkError.INVALID_STATE(message = "Claimed verification operation conflicts with its original request"))
                else if (original.expiresAt <= now) Err(IdkError.INVALID_STATE(message = "Claimed verification operation has expired"))
                else Ok(original.toPublic(json))
            }
        }
    }

    /** Whole-session configuration writes may not overwrite a concurrent response or alter request pins. */
    private suspend fun updateClaimedSnapshot(key: String, value: AuthorizationSession): IdkResult<StoreMetadata, IdkError> {
        val store = durableVersioning().getOrElse { return Err(it) }
        val head = store.getHead(namespace, claimedStorageKey(key)).getOrElse { return Err(it) }
            ?: return Err(IdkError.INVALID_STATE(message = "Claimed session must be created atomically"))
        val existing = head.value
        val public = existing.toPublic(json)
        if (public.copy(callback = value.callback, directPostResponseRedirectUri = value.directPostResponseRedirectUri) != value) {
            return Err(IdkError.INVALID_STATE(message = "Stale or altered claimed authorization session snapshot"))
        }
        if (public == value) return Ok(StoreMetadata(existing.createdAt, existing.expiresAt))
        if (existing.status != AuthorizationSessionStatus.AUTHORIZATION_REQUEST_CREATED.name) return Err(
            IdkError.INVALID_STATE(message = "Claimed session configuration is immutable after request retrieval"),
        )
        val now = clock.now().toEpochMilliseconds()
        if (now >= existing.expiresAt) return Err(IdkError.INVALID_STATE(message = "Claimed session expired"))
        val updated = toEntry(value, now, existing.expiresAt).copy(claimFingerprint = existing.claimFingerprint)
        return when (store.append(namespace, claimedStorageKey(key), head.versionId, updated, (existing.expiresAt - now).milliseconds).getOrElse { return Err(it) }) {
            is KvVersionAppendResult.Applied -> Ok(StoreMetadata(existing.createdAt, existing.expiresAt))
            is KvVersionAppendResult.Conflict -> Err(IdkError.INVALID_STATE(message = "Concurrent claimed session update"))
        }
    }

    private suspend fun update(
        correlationId: String,
        dispatch: Boolean = true,
        transform: (AuthorizationSessionEntry, nowEpochMillis: Long) -> AuthorizationSessionEntry,
    ): IdkResult<AuthorizationSession, IdkError> {
        val now = clock.now().toEpochMilliseconds()

        val versionStore = if (isClaimed(correlationId)) durableVersioning().getOrElse { return Err(it) } else null
        val head = versionStore?.getHead(namespace, claimedStorageKey(correlationId))?.getOrElse { return Err(it) }
        val existing =
            (if (versionStore != null) Ok(head?.value) else kv.get(namespace, correlationId)).getOrElse { e ->
                return Err(
                    IdkError.fromString(
                        message = "Failed to read authorization session: ${e.message}",
                        exception = IllegalStateException(e.toString()),
                        code = "OID4VP_AUTH_SESSION_STORE_ERROR",
                    ),
                )
            } ?: return Err(IdkError.NOT_FOUND_ERROR(resource = "authorizationSession:$correlationId", message = "Authorization session not found"))

        if (existing.expiresAt <= now) {
            kv.delete(namespace, correlationId)
            return Err(IdkError.fromString(message = "Authorization session expired", code = "OID4VP_AUTH_SESSION_EXPIRED"))
        }

        val updated = transform(existing, now)
        if (versionStore != null) {
            if (existing.parsedResponse != null && updated.parsedResponse != existing.parsedResponse) {
                return Err(IdkError.INVALID_STATE(message = "Claimed verification response is immutable once received"))
            }
            if (updated.status == AuthorizationSessionStatus.AUTHORIZATION_RESPONSE_VERIFIED.name &&
                (existing.parsedResponse == null || updated.validationResult?.valid != true)) {
                return Err(IdkError.INVALID_STATE(message = "Claimed verification requires a received response and successful verifier result"))
            }
        }
        // Completed verification cannot be reopened by response ingestion on either storage path.
        if (existing.status in setOf(AuthorizationSessionStatus.AUTHORIZATION_RESPONSE_VERIFIED.name, AuthorizationSessionStatus.ERROR.name)) {
            if (existing.copy(updatedAt = updated.updatedAt) == updated) return Ok(existing.toPublic(json))
            return Err(IdkError.INVALID_STATE(message = "Completed authorization verification is immutable"))
        }
        if (versionStore != null) {
            val result = versionStore.append(namespace, claimedStorageKey(correlationId), head?.versionId, updated, (existing.expiresAt - now).milliseconds).getOrElse { return Err(it) }
            if (result is KvVersionAppendResult.Conflict) return Err(IdkError.INVALID_STATE(message = "Concurrent claimed verification update"))
            val public = updated.toPublic(json)
            if (dispatch) {
                val previous = existing.toPublic(json)
                emitStatusTransition(previous, public)
                if (previous.status != public.status) dispatchIfConfigured(public)
            }
            return Ok(public)
        }
        val ttlSecondsRemaining = ((updated.expiresAt - now).coerceAtLeast(0L) / AUTHORIZATION_SESSION_MILLIS_PER_SECOND).coerceAtLeast(1L)

        kv.put(namespace, correlationId, updated, ttlSecondsRemaining.seconds).getOrElse { e ->
            return Err(IdkError.fromString(message = "Failed to update authorization session: ${e.message}", exception = IllegalStateException(e.toString()), code = "OID4VP_AUTH_SESSION_STORE_ERROR"))
        }

        val previous = existing.toPublic(json)
        val public = updated.toPublic(json)
        if (dispatch) {
            emitStatusTransition(previous, public)
            if (previous.status != public.status) dispatchIfConfigured(public)
        }
        return Ok(public)
    }

    private suspend fun emitStatusTransition(
        previous: AuthorizationSession,
        current: AuthorizationSession,
    ) {
        if (previous.status == current.status) return
        eventService?.emitOid4vpSessionHistoryEvent(
            type = Oid4vpVerifierSessionEventTypes.STATUS_CHANGED,
            origin = "oid4vp-authorization-session-store",
            session = current,
            oldState = previous.status.name,
            newState = current.status.name,
            stage = when (current.status) {
                AuthorizationSessionStatus.AUTHORIZATION_REQUEST_RETRIEVED -> "REQUEST_RETRIEVED"
                AuthorizationSessionStatus.AUTHORIZATION_RESPONSE_RECEIVED -> "RESPONSE_RECEIVED"
                AuthorizationSessionStatus.AUTHORIZATION_RESPONSE_VERIFIED -> "RESPONSE_VERIFIED"
                AuthorizationSessionStatus.ERROR -> "ERROR"
                else -> "STATUS"
            },
            outcome = if (current.status == AuthorizationSessionStatus.ERROR) "FAILED" else "SUCCEEDED",
        )
    }

    private suspend fun dispatchIfConfigured(session: AuthorizationSession) {
        val callback = session.callback ?: return
        val shouldEmit = callback.statuses.isEmpty() || callback.statuses.contains(session.status)
        if (!shouldEmit) {
            return
        }

        // Mapped from the session handed in. Every immediate caller passes the snapshot it just
        // persisted, so the callback describes that transition even when another one follows. The
        // deferred path hands in the stored session read when it dispatches.
        val status = statusResponseMapper.build(session, callback.verifiedData?.modes.orEmpty())

        eventService?.emitOid4vpSessionHistoryEvent(
            type = Oid4vpVerifierSessionEventTypes.CALLBACK_ATTEMPTED,
            origin = "oid4vp-authorization-session-store",
            session = session,
            oldState = session.status.name,
            newState = session.status.name,
            stage = "CALLBACK",
            outcome = "ATTEMPTED",
        )
        callbackDispatcher.dispatch(callback.url, status).fold(
            success = {
                eventService?.emitOid4vpSessionHistoryEvent(
                    type = Oid4vpVerifierSessionEventTypes.CALLBACK_SUCCEEDED,
                    origin = "oid4vp-authorization-session-store",
                    session = session,
                    oldState = session.status.name,
                    newState = session.status.name,
                    stage = "CALLBACK",
                    outcome = "SUCCEEDED",
                )
            },
            failure = { e ->
                eventService?.emitOid4vpSessionHistoryEvent(
                    type = Oid4vpVerifierSessionEventTypes.CALLBACK_FAILED,
                    origin = "oid4vp-authorization-session-store",
                    session = session,
                    oldState = session.status.name,
                    newState = session.status.name,
                    stage = "CALLBACK",
                    outcome = "FAILED",
                    errorCode = "callback_dispatch_failed",
                )
                // Best-effort: do not fail the main flow because callback delivery failed.
                log.warn("Failed to dispatch authorization session callback: ${e.message.defaultMessage}")
            },
        )
    }

    private fun generateSecureId(): String {
        val bytes = CryptographyRandom.nextBytes(RANDOM_BYTES_SIZE)
        return bytes.encodeToHex()
    }

    private companion object {
        fun parseVpToken(vpTokenRaw: String): VpToken? {
            return try {
                val trimmed = vpTokenRaw.trim()
                if (!trimmed.startsWith("{")) {
                    return null
                }
                val jsonElement = Json.parseToJsonElement(trimmed)
                VpToken.fromJson(jsonElement)
            } catch (_: Exception) {
                // Ignored: vp_token is not valid JSON
                null
            }
        }
    }
}
