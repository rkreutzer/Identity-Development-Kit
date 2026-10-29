/* Copyright 2026 Sphereon International B.V. Licensed under the Apache License, Version 2.0. */
package com.sphereon.oauth2.server.authorization.impl.command

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.log.LogLevel
import com.sphereon.core.defaults.random.defaultSecureRandom
import com.sphereon.crypto.core.KeyInfo
import com.sphereon.crypto.core.KeyType
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.crypto.jose.jws.JwtCompactResult
import com.sphereon.crypto.jose.jws.JwtService
import com.sphereon.crypto.jose.jws.JwtServiceImpl
import com.sphereon.crypto.jose.jws.command.CreateJwsArgs
import com.sphereon.crypto.resolution.managed.ManagedOptsKeyInfo
import com.sphereon.oauth2.common.config.OAuth2ServerInstanceConfig
import com.sphereon.oauth2.common.config.OAuth2ServersConfig
import com.sphereon.oauth2.common.model.GrantType
import com.sphereon.oauth2.server.authorization.command.CreateAccessTokenArgs
import com.sphereon.oauth2.server.authorization.command.CreateIdTokenArgs
import com.sphereon.oauth2.server.authorization.error.AuthorizationServerError
import com.sphereon.oauth2.server.authorization.impl.command.oidc.CreateIdTokenCommandImpl
import com.sphereon.oauth2.server.authorization.impl.command.token.CreateAccessTokenCommandImpl
import com.sphereon.oauth2.server.authorization.impl.config.RecordingSessionLogService
import com.sphereon.oauth2.server.authorization.impl.storage.memory.InMemoryOAuth2BackingStorageImpl
import com.sphereon.oauth2.server.authorization.impl.storage.memory.InMemoryTokenStorageImpl
import com.sphereon.oauth2.server.authorization.impl.testutil.*
import com.sphereon.oauth2.server.authorization.model.AccessTokenData
import com.sphereon.oauth2.server.authorization.model.ClientRegistration
import com.sphereon.oauth2.server.authorization.storage.OidcLoginSessionIdProvider
import com.sphereon.oauth2.server.authorization.storage.TokenStorage
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class TokenIssuanceErrorLoggingTest {
    private val ctx = OAuth2ServerTestContext("token-issuance-error-logging", this)
    private val recording = RecordingSessionLogService()
    private val execution = object : SessionExecution by ctx.execution {
        override val log = recording
    }
    private val config = TestOAuth2ServersConfigProvider(OAuth2ServersConfig(
        servers = mapOf("default" to OAuth2ServerInstanceConfig(issuer = "https://as.example.com")),
    ))
    private val resolver = fixedSigningIdentifierResolver(ManagedOptsKeyInfo(identifier = KeyInfo<KeyType>(
        alias = SECRET, kid = SECRET, signatureAlgorithm = SignatureAlgorithm.ECDSA_SHA256,
    )))
    private val delegateJwt = (ctx.session.graph as JwtServiceImpl.Graph).jwtService
    private val storage = InMemoryTokenStorageImpl(InMemoryOAuth2BackingStorageImpl())
    private val failingSigner = object : JwtService by delegateJwt {
        override suspend fun createJwsCompact(args: CreateJwsArgs): IdkResult<JwtCompactResult, IdkError> =
            Err(IdkError.fromString(code = "fixture_signing_refused", message = SECRET))
    }

    @Test
    fun accessTokenSigningFailureLogsCodeWithoutSensitiveDetails() = runTest {
        val result = accessCommand(failingSigner, storage).execute(accessArgs())
        assertTrue(result.isErr)
        assertSafeError("access-token-signing", "fixture_signing_refused")
    }

    @Test
    fun accessTokenStorageFailureLogsCodeWithoutTokenOrStorageDetails() = runTest {
        val signer = object : JwtService by delegateJwt {
            override suspend fun createJwsCompact(args: CreateJwsArgs): IdkResult<JwtCompactResult, IdkError> =
                Ok(JwtCompactResult(jwt = SECRET))
        }
        val failingStorage = object : TokenStorage by storage {
            override suspend fun storeAccessToken(token: String, data: AccessTokenData): IdkResult<Unit, AuthorizationServerError.StorageError> =
                Err(AuthorizationServerError.StorageError(operation = "store", details = SECRET))
        }
        assertTrue(accessCommand(signer, failingStorage).execute(accessArgs()).isErr)
        assertSafeError("access-token-storage", "storage_error")
    }

    @Test
    fun idTokenSigningFailureLogsCodeWithoutSensitiveDetails() = runTest {
        assertTrue(idCommand(failingSigner).execute(CreateIdTokenArgs(subject = SECRET, clientId = "portal", accessToken = SECRET)).isErr)
        assertSafeError("id-token-signing", "fixture_signing_refused")
    }

    @Test
    fun signingCancellationPropagatesWithoutErrorLogging() = runTest {
        val cancelledSigner = object : JwtService by delegateJwt {
            override suspend fun createJwsCompact(args: CreateJwsArgs): IdkResult<JwtCompactResult, IdkError> =
                throw CancellationException(SECRET)
        }
        assertFailsWith<CancellationException> { accessCommand(cancelledSigner, storage).execute(accessArgs()) }
        assertFailsWith<CancellationException> {
            idCommand(cancelledSigner).execute(CreateIdTokenArgs(subject = SECRET, clientId = "portal"))
        }
        assertTrue(recording.messages.none { it.level == LogLevel.ERROR })
    }

    private fun accessArgs() = CreateAccessTokenArgs(subject = SECRET, clientId = "portal", audience = listOf("api"))
    private fun accessCommand(signer: JwtService, tokens: TokenStorage) = CreateAccessTokenCommandImpl(
        execution = execution, jwtService = signer, tokenStorage = tokens, secureRandom = defaultSecureRandom(),
        configProvider = config, asInstanceIdProvider = fixedAsInstanceIdProvider(), signingIdentifierResolver = resolver,
    )
    private fun idCommand(signer: JwtService) = CreateIdTokenCommandImpl(
        execution = execution, jwtService = signer, configProvider = config, asInstanceIdProvider = fixedAsInstanceIdProvider(),
        signingIdentifierResolver = resolver,
        clientRegistry = StubClientRegistry(mapOf("portal" to ClientRegistration(clientId = "portal", grantTypes = listOf(GrantType.AUTHORIZATION_CODE)))),
        sessionParticipationRecorders = emptySet(),
        loginSessionIdProvider = object : OidcLoginSessionIdProvider { override fun currentLoginSessionId(): String? = null },
    )
    private fun assertSafeError(stage: String, code: String) {
        val error = recording.messages.single { it.level == LogLevel.ERROR }
        assertTrue(error.message.contains("stage=$stage"))
        assertTrue(error.message.contains(code))
        assertFalse(recording.messages.any { SECRET in it.toString() })
        assertEquals(null, error.exception)
        assertEquals(null, error.errorResult)
    }
    private companion object { const val SECRET = "sensitive-token-password-key-sentinel" }
}
