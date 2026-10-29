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
import com.sphereon.di.session.SessionScope
import com.sphereon.ktor.http.client.provider.HttpClientProvider
import com.sphereon.ktor.http.client.provider.counterpartyEgressIf
import com.sphereon.ktor.http.client.provider.isCounterpartyEgress
import com.sphereon.oauth2.client.command.ExchangeTokenCommand
import com.sphereon.oauth2.client.token.DefaultOAuth2TokenEndpointSelector
import com.sphereon.oauth2.client.token.OAuth2TokenEndpointSelection
import com.sphereon.oauth2.client.token.OAuth2TokenEndpointTransport
import com.sphereon.oauth2.client.token.OAuth2TokenEndpointTransportArgs
import com.sphereon.oauth2.client.util.isSecureUrl
import com.sphereon.oauth2.client.validation.validateTokenErrorResponse
import com.sphereon.oauth2.client.validation.validateTokenRequest
import com.sphereon.oauth2.client.validation.validateTokenResponse
import com.sphereon.oauth2.common.command.ApplyClientAuthenticationArgs
import com.sphereon.oauth2.common.command.ApplyClientAuthenticationCommand
import com.sphereon.oauth2.common.error.Oauth2Error
import com.sphereon.oauth2.common.model.ClientAssertion
import com.sphereon.oauth2.common.model.ClientAuthenticationConfig
import com.sphereon.oauth2.common.model.ClientAuthenticationMethod
import com.sphereon.oauth2.common.model.ClientCredentials
import com.sphereon.oauth2.common.model.TokenErrorResponse
import com.sphereon.oauth2.common.model.TokenRequest
import com.sphereon.oauth2.common.model.TokenResponse
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import io.konform.validation.Invalid
import io.konform.validation.Valid
import io.ktor.client.HttpClient
import io.ktor.client.request.forms.submitForm
import io.ktor.client.request.headers
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.Parameters
import io.ktor.http.isSuccess
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlin.coroutines.cancellation.CancellationException

@Inject
@SingleIn(SessionScope::class)
@ContributesBinding(SessionScope::class)
class OAuth2TokenEndpointTransportImpl(
    private val httpClients: HttpClientProvider,
    private val applyClientAuthenticationCommand: ApplyClientAuthenticationCommand,
) : OAuth2TokenEndpointTransport {
    private val json = Json {
        ignoreUnknownKeys = true
        isLenient = true
    }

    override suspend fun exchange(args: OAuth2TokenEndpointTransportArgs): IdkResult<TokenResponse, Oauth2Error> {
        var stage = "validation"
        return try {
            exchangeAtEndpoint(args) { stage = it }.also { result ->
                if (result.isErr) logFailure(stage)
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (failure: Throwable) {
            logFailure(stage, failure)
            throw failure
        }
    }

    private suspend fun exchangeAtEndpoint(
        args: OAuth2TokenEndpointTransportArgs,
        markStage: (String) -> Unit,
    ): IdkResult<TokenResponse, Oauth2Error> {
        val explicitlySelectedAuthMethod = args.tokenRequest.tokenEndpointAuthMethod
        val authMethod = explicitlySelectedAuthMethod ?: ClientAuthenticationMethod.CLIENT_SECRET_POST
        val endpointResult = DefaultOAuth2TokenEndpointSelector.select(
            OAuth2TokenEndpointSelection(
                configuredTokenEndpoint = args.configuredTokenEndpoint,
                authenticationMethod = authMethod,
                authorizationServerMetadata = args.authorizationServerMetadata,
                callerAuthorizedTokenEndpoints = args.callerAuthorizedTokenEndpoints,
            ),
        )
        if (endpointResult.isErr) return Err(endpointResult.error)
        val endpoint = endpointResult.value.uri

        if (!isSecureUrl(endpoint)) {
            return validationFailure(
                "Token endpoint must be an HTTPS URL (HTTP only allowed for localhost)",
                "token_endpoint must start with https:// (HTTP only allowed for localhost)",
            )
        }

        when (val validation = validateTokenRequest(args.tokenRequest)) {
            is Invalid -> return validationFailure(
                "Token request validation failed",
                *validation.errors.map { "${it.dataPath}: ${it.message}" }.toTypedArray(),
            )
            is Valid -> Unit
        }

        val authentication = args.clientAuthentication ?: deriveClientAuthentication(args.tokenRequest, authMethod)
        if (
            authentication == null ||
            !authentication.matches(
                method = authMethod,
                allowLegacyAnonymousPost = explicitlySelectedAuthMethod == null,
            )
        ) {
            return validationFailure(
                "Token endpoint client authentication is incomplete or does not match the selected method",
                "A matching client authentication configuration is required",
            )
        }

        if (authMethod.isMutualTls()) {
            val governed = args.httpClientRequestContext
                ?: return validationFailure(
                    "Mutual TLS token endpoint authentication requires a governed HTTP context",
                    "A governed context with an endpoint-bound client TLS identity is required",
                )
            if (governed.clientTlsIdentity == null) {
                return validationFailure(
                    "Mutual TLS token endpoint authentication requires a client TLS identity",
                    "The governed context has no client TLS identity selected for the token endpoint",
                )
            }
            val targetValidation = runCatching {
                governed.toHttpClientOptions().urlValidation?.validate(io.ktor.http.Url(endpoint))
                    ?: error("Governed HTTP context has no exact-target validation policy")
            }
            if (targetValidation.isFailure) {
                return validationFailure(
                    "Mutual TLS token endpoint does not match the governed HTTP context",
                    targetValidation.exceptionOrNull()?.message ?: "Effective token endpoint is not approved",
                )
            }
        }

        markStage("client-authentication")
        val authResult = applyClientAuthenticationCommand.execute(ApplyClientAuthenticationArgs(authentication, endpoint))
        if (authResult.isErr) {
            return validationFailure(
                "Failed to apply token endpoint client authentication",
                authResult.error.message.defaultMessage,
            )
        }

        markStage("request-assembly")
        val auth = authResult.value
        val parameters = buildFormParameters(args.tokenRequest) + auth.bodyParameters.entries.map { it.key to it.value }

        return try {
            markStage("http-client")
            withSelectedClient(args) { client ->
                markStage("token-request")
                val response = client.submitForm(
                    url = endpoint,
                    formParameters = Parameters.build {
                        parameters.forEach { (name, value) -> append(name, value) }
                    },
                ) {
                    headers {
                        append(HttpHeaders.Accept, ContentType.Application.Json.toString())
                        auth.headers.forEach { (name, value) -> append(name, value) }
                        args.tokenRequest.dpop?.let { append("DPoP", it) }
                        args.tokenRequest.additionalHeaders.forEach { (name, value) -> append(name, value) }
                    }
                }
                markStage("token-response")
                parseResponse(response)
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (expected: Exception) {
            logFailure("token-exchange", expected)
            Err(
                Oauth2Error.FetchFailed(
                    failureMessage = "Failed to exchange OAuth2 token",
                    cause = expected,
                ),
            )
        }
    }

    private fun logFailure(stage: String, failure: Throwable? = null) {
        val type = failure?.let { it::class.simpleName }
            ?.takeIf { it.matches(Regex("[A-Za-z][A-Za-z0-9_]{0,79}")) } ?: "unavailable"
        Log.app().withTag("OAuth2TokenEndpointTransport").warn(
            "OAuth2 token exchange refused stage=$stage error_type=$type",
        )
    }

    private suspend fun withSelectedClient(
        args: OAuth2TokenEndpointTransportArgs,
        block: suspend (HttpClient) -> IdkResult<TokenResponse, Oauth2Error>,
    ): IdkResult<TokenResponse, Oauth2Error> {
        val governed = args.httpClientRequestContext
        if (governed != null) return httpClients.withClient(governed, block)

        val holderEgress = isCounterpartyEgress()
        return httpClients.withClient(
            commandId = ExchangeTokenCommand.COMMAND_ID,
            overrides = { options ->
                val existingConfig = options.additionalConfig
                options.copy(
                    followRedirects = false,
                    additionalConfig = {
                        existingConfig?.invoke(this)
                        followRedirects = false
                    },
                ).counterpartyEgressIf(holderEgress)
            },
            block = block,
        )
    }

    private suspend fun parseResponse(response: HttpResponse): IdkResult<TokenResponse, Oauth2Error> {
        val responseBody = response.bodyAsText()
        val dpopNonce = response.headers["DPoP-Nonce"]

        if (response.status.isSuccess()) {
            val decoded = json.decodeFromString<TokenResponse>(responseBody)
            when (val validation = validateTokenResponse(decoded)) {
                is Invalid -> return validationFailure(
                    "Token response validation failed",
                    *validation.errors.map { "${it.dataPath}: ${it.message}" }.toTypedArray(),
                )
                is Valid -> Unit
            }
            return Ok(if (dpopNonce != null && decoded.dpopNonce == null) decoded.copy(dpopNonce = dpopNonce) else decoded)
        }

        val fallbackCode = when (response.status) {
            HttpStatusCode.Unauthorized -> "invalid_token"
            HttpStatusCode.BadRequest -> "invalid_request"
            else -> "unknown_error"
        }
        val errorResponse = try {
            val decoded = json.decodeFromString<TokenErrorResponse>(responseBody)
            when (validateTokenErrorResponse(decoded)) {
                is Invalid -> throw IllegalArgumentException("Invalid OAuth 2.0 error response")
                is Valid -> decoded
            }
        } catch (expected: Exception) {
            TokenErrorResponse(
                error = fallbackCode,
                errorDescription = "Failed to parse error response: ${expected.message}",
            )
        }

        return if (errorResponse.error == "use_dpop_nonce" && dpopNonce != null) {
            Err(Oauth2Error.DpopNonceRequired(dpopNonce))
        } else {
            Err(Oauth2Error.ErrorResponse(errorResponse.error, errorResponse.errorDescription, errorResponse.errorUri))
        }
    }

    private fun deriveClientAuthentication(
        request: TokenRequest,
        method: ClientAuthenticationMethod,
    ): ClientAuthenticationConfig? = when (method) {
        ClientAuthenticationMethod.CLIENT_SECRET_BASIC -> credentials(request)?.let(ClientAuthenticationConfig::Basic)
        ClientAuthenticationMethod.CLIENT_SECRET_POST -> credentials(request)?.let(ClientAuthenticationConfig::Post)
            ?: ClientAuthenticationConfig.Anonymous
        ClientAuthenticationMethod.CLIENT_SECRET_JWT -> assertion(request)?.let(ClientAuthenticationConfig::SecretJwt)
        ClientAuthenticationMethod.PRIVATE_KEY_JWT -> assertion(request)?.let(ClientAuthenticationConfig::PrivateKeyJwt)
        ClientAuthenticationMethod.NONE -> request.clientId?.let(ClientAuthenticationConfig::None)
            ?: ClientAuthenticationConfig.Anonymous
        ClientAuthenticationMethod.ATTEST_JWT_CLIENT_AUTH -> ClientAuthenticationConfig.Anonymous
        ClientAuthenticationMethod.TLS_CLIENT_AUTH,
        ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH,
        -> null
    }

    private fun credentials(request: TokenRequest): ClientCredentials? {
        val clientId = request.clientId ?: return null
        val clientSecret = request.clientSecret ?: return null
        return ClientCredentials(clientId, clientSecret)
    }

    private fun assertion(request: TokenRequest): ClientAssertion? {
        val clientId = request.clientId ?: return null
        val type = request.clientAssertionType ?: return null
        val assertion = request.clientAssertion ?: return null
        return ClientAssertion(clientId, type, assertion)
    }

    private fun ClientAuthenticationConfig.matches(
        method: ClientAuthenticationMethod,
        allowLegacyAnonymousPost: Boolean,
    ): Boolean = when (method) {
        ClientAuthenticationMethod.CLIENT_SECRET_BASIC -> this is ClientAuthenticationConfig.Basic
        ClientAuthenticationMethod.CLIENT_SECRET_POST ->
            this is ClientAuthenticationConfig.Post || (allowLegacyAnonymousPost && this is ClientAuthenticationConfig.Anonymous)
        ClientAuthenticationMethod.CLIENT_SECRET_JWT -> this is ClientAuthenticationConfig.SecretJwt
        ClientAuthenticationMethod.PRIVATE_KEY_JWT -> this is ClientAuthenticationConfig.PrivateKeyJwt
        ClientAuthenticationMethod.NONE -> this is ClientAuthenticationConfig.None || this is ClientAuthenticationConfig.Anonymous
        ClientAuthenticationMethod.ATTEST_JWT_CLIENT_AUTH -> this is ClientAuthenticationConfig.AttestationJwt || this is ClientAuthenticationConfig.Anonymous
        ClientAuthenticationMethod.TLS_CLIENT_AUTH,
        ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH,
        -> this is ClientAuthenticationConfig.MutualTls
    }

    private fun ClientAuthenticationMethod.isMutualTls(): Boolean =
        this == ClientAuthenticationMethod.TLS_CLIENT_AUTH ||
            this == ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH

    private fun buildFormParameters(request: TokenRequest): List<Pair<String, String>> = buildList {
        add("grant_type" to request.grantType)
        request.code?.let { add("code" to it) }
        request.redirectUri?.let { add("redirect_uri" to it) }
        request.codeVerifier?.let { add("code_verifier" to it) }
        request.refreshToken?.let { add("refresh_token" to it) }
        request.preAuthorizedCode?.let { add("pre-authorized_code" to it) }
        request.txCode?.let { add("tx_code" to it) }
        request.scope?.let { add("scope" to it) }
        request.resource.forEach { add("resource" to it) }
        request.audience.forEach { add("audience" to it) }
        request.subjectToken?.let { add("subject_token" to it) }
        request.subjectTokenType?.let { add("subject_token_type" to it) }
        request.actorToken?.let { add("actor_token" to it) }
        request.actorTokenType?.let { add("actor_token_type" to it) }
        request.requestedTokenType?.let { add("requested_token_type" to it) }
        request.authorizationDetails?.let { add("authorization_details" to it.toString()) }
        request.additionalParameters.forEach { (name, value) ->
            add(name to if (value is JsonPrimitive) value.contentOrNull ?: value.toString() else value.toString())
        }
    }

    private fun validationFailure(
        message: String,
        vararg errors: String,
    ): IdkResult<Nothing, Oauth2Error> = Err(Oauth2Error.ValidationFailed(message, errors.toList()))
}


