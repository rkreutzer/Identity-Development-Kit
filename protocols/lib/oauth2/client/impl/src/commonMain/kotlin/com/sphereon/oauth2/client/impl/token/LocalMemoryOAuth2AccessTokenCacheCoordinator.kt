/*
 * Copyright 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0.
 */

package com.sphereon.oauth2.client.impl.token

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.log.Log
import com.sphereon.oauth2.client.token.DefaultOAuth2TokenEndpointSelector
import com.sphereon.oauth2.client.token.OAuth2AccessTokenBindingMode
import com.sphereon.oauth2.client.token.OAuth2AccessTokenCacheCoordinator
import com.sphereon.oauth2.client.token.OAuth2AccessTokenCacheKey
import com.sphereon.oauth2.client.token.OAuth2AccessTokenClock
import com.sphereon.oauth2.client.token.OAuth2CachedAccessToken
import com.sphereon.oauth2.client.token.OAuth2ProtectedResourceResponse
import com.sphereon.oauth2.client.token.OAuth2TokenEndpointSelection
import com.sphereon.oauth2.client.token.OAuth2TokenEndpointTransport
import com.sphereon.oauth2.client.token.OAuth2TokenEndpointTransportArgs
import com.sphereon.oauth2.client.token.normalizeOAuth2CacheSelectors
import com.sphereon.oauth2.client.util.isSecureUrl
import com.sphereon.oauth2.common.error.Oauth2Error
import com.sphereon.oauth2.common.model.ClientAuthenticationMethod
import com.sphereon.oauth2.common.model.TokenResponse
import com.sphereon.di.session.SessionScope
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import io.ktor.http.Url
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Instant

/**
 * Process-local access-token coordinator.
 *
 * The server resource-token `InMemoryTokenCacheImpl` is intentionally not reused: it is keyed by
 * raw bearer token, stores validation payloads, and is not a concurrent acquisition cache. Core
 * `Cache`/`ScopedCache` implementations are also intentionally avoided because their backend
 * contract serializes values. This store keeps the access token only in private process memory.
 */
@Inject
@SingleIn(SessionScope::class)
@ContributesBinding(SessionScope::class)
class LocalMemoryOAuth2AccessTokenCacheCoordinator(
    private val tokenEndpointTransport: OAuth2TokenEndpointTransport,
    private val clock: OAuth2AccessTokenClock = OAuth2AccessTokenClock.System,
    private val expirySkew: Duration = DEFAULT_EXPIRY_SKEW,
) : OAuth2AccessTokenCacheCoordinator {
    private val stateMutex = Mutex()
    private val entries = mutableMapOf<OAuth2AccessTokenCacheKey, CacheEntry>()
    private val inFlight = mutableMapOf<OAuth2AccessTokenCacheKey, InFlightLoad>()
    private val keyEpochs = mutableMapOf<OAuth2AccessTokenCacheKey, Long>()
    private val tenantEpochs = mutableMapOf<String, Long>()

    init {
        require(expirySkew > Duration.ZERO) { "Access-token expiry skew must be positive" }
    }

    override suspend fun getOrAcquire(
        key: OAuth2AccessTokenCacheKey,
        transportArgs: OAuth2TokenEndpointTransportArgs,
    ): IdkResult<OAuth2CachedAccessToken, Oauth2Error> {
        validateAcquisition(key, transportArgs)?.let {
            Log.app().withTag("OAuth2AccessTokenCoordinator").warn("OAuth2 acquisition refused stage=validation")
            return Err(it)
        }

        return when (val decision = lookup(key)) {
            is LookupDecision.Hit -> Ok(decision.token)
            is LookupDecision.Await -> decision.deferred.await()
            is LookupDecision.Load -> acquire(key, transportArgs, decision.load)
        }
    }

    override suspend fun evict(key: OAuth2AccessTokenCacheKey) {
        stateMutex.withLock {
            entries.remove(key)
            keyEpochs[key] = keyEpoch(key) + 1L
            inFlight.remove(key)
        }
    }

    override suspend fun invalidateTenant(tenantId: String) {
        require(tenantId.isNotBlank()) { "tenantId must not be blank" }
        stateMutex.withLock {
            entries.keys.removeAll { it.tenantId == tenantId }
            inFlight.keys.removeAll { it.tenantId == tenantId }
            tenantEpochs[tenantId] = tenantEpoch(tenantId) + 1L
        }
    }

    override suspend fun <T> executeProtectedResource(
        key: OAuth2AccessTokenCacheKey,
        transportArgs: OAuth2TokenEndpointTransportArgs,
        request: suspend (OAuth2CachedAccessToken) -> OAuth2ProtectedResourceResponse<T>,
    ): IdkResult<OAuth2ProtectedResourceResponse<T>, Oauth2Error> {
        val firstToken = getOrAcquire(key, transportArgs)
        if (firstToken.isErr) return Err(firstToken.error)

        val firstResponse = request(firstToken.value)
        if (firstResponse.statusCode != HTTP_UNAUTHORIZED) return Ok(firstResponse)

        evictRejectedToken(key, firstToken.value)
        val replacementToken = getOrAcquire(key, transportArgs)
        if (replacementToken.isErr) return Err(replacementToken.error)
        return Ok(request(replacementToken.value))
    }

    private suspend fun lookup(key: OAuth2AccessTokenCacheKey): LookupDecision = stateMutex.withLock {
        val now = clock.now()
        entries[key]?.let { entry ->
            if (now < entry.usableUntil) return@withLock LookupDecision.Hit(entry.token)
            entries.remove(key)
        }

        inFlight[key]?.let { return@withLock LookupDecision.Await(it.deferred) }
        val load = InFlightLoad(
            deferred = CompletableDeferred(),
            keyEpoch = keyEpoch(key),
            tenantEpoch = tenantEpoch(key.tenantId),
        )
        inFlight[key] = load
        LookupDecision.Load(load)
    }

    private suspend fun acquire(
        key: OAuth2AccessTokenCacheKey,
        transportArgs: OAuth2TokenEndpointTransportArgs,
        load: InFlightLoad,
    ): IdkResult<OAuth2CachedAccessToken, Oauth2Error> {
        var completion: IdkResult<OAuth2CachedAccessToken, Oauth2Error>? = null
        var failure: Throwable? = null
        return try {
            val transported = tokenEndpointTransport.exchange(transportArgs)
            val result = if (transported.isErr) {
                Log.app().withTag("OAuth2AccessTokenCoordinator").warn("OAuth2 acquisition refused stage=token-transport")
                Err(transported.error)
            } else {
                val acquiredAt = clock.now()
                val token = transported.value.toMemoryOnlyToken(acquiredAt)
                val usableUntil = transported.value.cacheUsableUntil(acquiredAt)
                if (usableUntil != null) {
                    stateMutex.withLock {
                        val notInvalidated = load.keyEpoch == keyEpoch(key) && load.tenantEpoch == tenantEpoch(key.tenantId)
                        if (notInvalidated) entries[key] = CacheEntry(token, usableUntil)
                    }
                }
                Ok(token)
            }
            completion = result
            result
        } catch (expected: Throwable) {
            if (expected !is CancellationException) {
                val type = expected::class.simpleName?.takeIf { it.matches(Regex("[A-Za-z][A-Za-z0-9_]{0,79}")) } ?: "unavailable"
                Log.app().withTag("OAuth2AccessTokenCoordinator").warn(
                    "OAuth2 acquisition failed stage=acquire error_type=$type",
                )
            }
            failure = expected
            throw expected
        } finally {
            completeAndRemoveLoad(key, load, completion, failure)
        }
    }

    private suspend fun completeAndRemoveLoad(
        key: OAuth2AccessTokenCacheKey,
        load: InFlightLoad,
        completion: IdkResult<OAuth2CachedAccessToken, Oauth2Error>?,
        failure: Throwable?,
    ) = withContext(NonCancellable) {
        if (completion != null) {
            load.deferred.complete(completion)
            stateMutex.withLock {
                if (inFlight[key] === load) inFlight.remove(key)
            }
        } else {
            stateMutex.withLock {
                if (inFlight[key] === load) inFlight.remove(key)
            }
            load.deferred.completeExceptionally(failure ?: IllegalStateException("Token acquisition ended without a result"))
        }
    }

    private suspend fun evictRejectedToken(
        key: OAuth2AccessTokenCacheKey,
        rejectedToken: OAuth2CachedAccessToken,
    ) {
        stateMutex.withLock {
            val current = entries[key]
            if (current?.token === rejectedToken) {
                entries.remove(key)
                keyEpochs[key] = keyEpoch(key) + 1L
            }
        }
    }

    private fun validateAcquisition(
        key: OAuth2AccessTokenCacheKey,
        args: OAuth2TokenEndpointTransportArgs,
    ): Oauth2Error? {
        val governedContext = args.httpClientRequestContext
            ?: return validationFailure("Cached token acquisition requires a governed HTTP context")
        if (key.tenantId != governedContext.tenantId ||
            key.connectorId != governedContext.connectorId ||
            key.profileRevision != governedContext.connectorProfileRevision ||
            key.egressRevision != governedContext.egressProfileRevision ||
            key.trustDomainRevision != governedContext.trustDomainRevision ||
            key.anchorSetDigest != governedContext.anchorSetDigest
        ) {
            return validationFailure("Cache key security dimensions do not match the governed HTTP context")
        }

        val authMethod = args.tokenRequest.tokenEndpointAuthMethod ?: ClientAuthenticationMethod.CLIENT_SECRET_POST
        if (key.authenticationMethod != authMethod) {
            return validationFailure("Cache key authentication method does not match the token request")
        }

        val selected = DefaultOAuth2TokenEndpointSelector.select(
            OAuth2TokenEndpointSelection(
                configuredTokenEndpoint = args.configuredTokenEndpoint,
                authenticationMethod = authMethod,
                authorizationServerMetadata = args.authorizationServerMetadata,
                callerAuthorizedTokenEndpoints = args.callerAuthorizedTokenEndpoints,
            ),
        )
        if (selected.isErr) return selected.error
        if (selected.value.uri != key.effectiveTokenEndpoint || !isSecureUrl(key.effectiveTokenEndpoint)) {
            return validationFailure("Cache key token endpoint does not match the selected secure token endpoint")
        }
        val targetValidation = runCatching {
            governedContext.toHttpClientOptions().urlValidation?.validate(Url(key.effectiveTokenEndpoint))
                ?: error("Governed HTTP context has no exact-target validation policy")
        }
        if (targetValidation.isFailure) {
            return validationFailure("Cache key token endpoint does not match the governed HTTP context")
        }

        val requestScopes = normalizeOAuth2CacheSelectors(args.tokenRequest.scope.orEmpty().split(WHITESPACE))
        if (key.scopes != requestScopes ||
            key.resources != normalizeOAuth2CacheSelectors(args.tokenRequest.resource) ||
            key.audiences != normalizeOAuth2CacheSelectors(args.tokenRequest.audience)
        ) {
            return validationFailure("Cache key selectors do not match the token request")
        }

        val requiresCertificate = authMethod.isMutualTls() ||
            key.accessTokenBindingMode == OAuth2AccessTokenBindingMode.CERTIFICATE_BOUND
        if (requiresCertificate) {
            val identity = governedContext.clientTlsIdentity
                ?: return validationFailure("Certificate-bound token acquisition requires a governed client TLS identity")
            if (identity.certificateFingerprint != key.clientCertificateFingerprint) {
                return validationFailure("Cache key certificate fingerprint does not match the governed client TLS identity")
            }
        }
        return null
    }

    private fun TokenResponse.toMemoryOnlyToken(acquiredAt: Instant): OAuth2CachedAccessToken {
        val expiresAt = expiresIn?.takeIf { it > 0 }?.let { acquiredAt + it.toLong().seconds }
        return OAuth2CachedAccessToken(
            accessToken = accessToken,
            tokenType = tokenType,
            scope = scope,
            expiresAt = expiresAt,
        )
    }

    private fun TokenResponse.cacheUsableUntil(acquiredAt: Instant): Instant? {
        val lifetimeSeconds = expiresIn?.toLong() ?: return null
        if (lifetimeSeconds <= 0L || lifetimeSeconds.seconds <= expirySkew) return null
        return acquiredAt + lifetimeSeconds.seconds - expirySkew
    }

    private fun keyEpoch(key: OAuth2AccessTokenCacheKey): Long = keyEpochs[key] ?: 0L

    private fun tenantEpoch(tenantId: String): Long = tenantEpochs[tenantId] ?: 0L

    private fun validationFailure(message: String): Oauth2Error = Oauth2Error.ValidationFailed(
        failureMessage = message,
        validationErrors = listOf(message),
    )

    private data class CacheEntry(
        val token: OAuth2CachedAccessToken,
        val usableUntil: Instant,
    )

    private data class InFlightLoad(
        val deferred: CompletableDeferred<IdkResult<OAuth2CachedAccessToken, Oauth2Error>>,
        val keyEpoch: Long,
        val tenantEpoch: Long,
    )

    private sealed interface LookupDecision {
        data class Hit(val token: OAuth2CachedAccessToken) : LookupDecision

        data class Await(
            val deferred: CompletableDeferred<IdkResult<OAuth2CachedAccessToken, Oauth2Error>>,
        ) : LookupDecision

        data class Load(val load: InFlightLoad) : LookupDecision
    }

    private companion object {
        val DEFAULT_EXPIRY_SKEW: Duration = 30.seconds
        const val HTTP_UNAUTHORIZED = 401
        val WHITESPACE = Regex("\\s+")
    }
}

private fun ClientAuthenticationMethod.isMutualTls(): Boolean =
    this == ClientAuthenticationMethod.TLS_CLIENT_AUTH || this == ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH


