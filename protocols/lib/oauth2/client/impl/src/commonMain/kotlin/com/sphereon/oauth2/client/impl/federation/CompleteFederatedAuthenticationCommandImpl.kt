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

package com.sphereon.oauth2.client.impl.federation

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.random.SecureRandom
import com.sphereon.core.api.service.TypedServiceCommandAdapter
import com.sphereon.crypto.core.jose.JwkSet
import com.sphereon.crypto.jose.jws.JwtService
import com.sphereon.di.session.SessionScope
import com.sphereon.ktor.http.client.provider.HttpClientFactory
import com.sphereon.ktor.http.client.provider.HttpClientOptions
import com.sphereon.oauth2.client.command.AuthorizationResponseSource
import com.sphereon.oauth2.client.command.CompleteFederatedAuthenticationArgs
import com.sphereon.oauth2.client.command.CompleteFederatedAuthenticationCommand
import com.sphereon.oauth2.client.command.FederatedAuthenticationResult
import com.sphereon.oauth2.client.command.ParseAuthorizationResponseArgs
import com.sphereon.oauth2.client.command.ParseAuthorizationResponseCommand
import com.sphereon.oauth2.client.command.ParsedAuthorizationResponse
import com.sphereon.oauth2.client.util.encodeQueryParameters
import com.sphereon.oauth2.common.command.ValidateIdTokenArgs
import com.sphereon.oauth2.common.command.ValidateIdTokenCommand
import com.sphereon.oauth2.common.model.IdTokenValidationOptions
import com.sphereon.oauth2.common.model.TokenResponse
import dev.zacsweers.metro.ExposeImplBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.isSuccess
import kotlinx.coroutines.CancellationException
import kotlinx.serialization.json.jsonObject
import kotlin.time.Clock

/**
 * Callback, code redemption and ID Token verification for an RP that registered automatically
 * (OpenID Federation for OpenID Connect 1.1 §12.1.2, §12.1.4).
 *
 * The client authenticates at the token endpoint with `private_key_jwt`, the method it registered and the OP declared
 * (§12.1.4); the assertion's only audience is the OP's Entity Identifier, its issuer. The ID Token is verified only
 * with the keys from the OP's resolved federation metadata, and only with the RP's registered
 * `id_token_signed_response_alg`.
 */
@Inject
@SingleIn(SessionScope::class)
@ExposeImplBinding
class CompleteFederatedAuthenticationCommandImpl(
    execution: SessionExecution,
    private val parseAuthorizationResponseCommand: ParseAuthorizationResponseCommand,
    private val validateIdTokenCommand: ValidateIdTokenCommand,
    private val httpClientFactory: HttpClientFactory,
    jwtService: JwtService,
    secureRandom: SecureRandom,
) : TypedServiceCommandAdapter<CompleteFederatedAuthenticationArgs, FederatedAuthenticationResult, IdkError>(
        commandId = CompleteFederatedAuthenticationCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<CompleteFederatedAuthenticationArgs>(),
        outputTypeToken = typeToken<FederatedAuthenticationResult>(),
    ),
    CompleteFederatedAuthenticationCommand {
    override val commandId: String get() = CompleteFederatedAuthenticationCommand.COMMAND_ID

    private val signer = FederatedRpJwtSigner(jwtService, secureRandom)

    override suspend fun supports(args: Any): Boolean = args is CompleteFederatedAuthenticationArgs

    override suspend fun doExecute(
        args: CompleteFederatedAuthenticationArgs,
        applyDuring: (CompleteFederatedAuthenticationArgs) -> CompleteFederatedAuthenticationArgs,
    ): IdkResult<FederatedAuthenticationResult, IdkError> {
        val applied = applyDuring(args)
        val provider = applied.provider
        val rp = applied.relyingParty
        val transaction = applied.transaction
        val now = Clock.System.now().epochSeconds

        if (transaction.providerEntityIdentifier != provider.entityIdentifier) {
            return federationFailure("invalid_request", "The transaction belongs to another OP")
        }
        if (transaction.clientId != rp.entityIdentifier || transaction.redirectUri != rp.redirectUri) {
            return federationFailure("invalid_request", "The transaction belongs to another RP or redirect URI")
        }
        providerProblem(provider, rp, now)?.let { return federationFailure("invalid_provider_metadata", it) }
        if (applied.callbackUrl.substringBefore('?').substringBefore('#') != transaction.redirectUri) {
            return federationFailure("invalid_request", "The authorization response arrived at another redirect URI")
        }

        val parsed = parseAuthorizationResponseCommand.execute(
            ParseAuthorizationResponseArgs(
                redirectUrl = applied.callbackUrl,
                source = AuthorizationResponseSource.QUERY,
                expectedState = transaction.state,
                expectedIssuer = provider.entityIdentifier,
                requireIssuer = provider.metadata.authorizationResponseIssParameterSupported == true,
            ),
        )
        if (parsed.isErr) return Err(parsed.error)
        val code = when (val response = parsed.value) {
            is ParsedAuthorizationResponse.Success -> response.response.code
            is ParsedAuthorizationResponse.Error ->
                return federationFailure(response.response.error, response.response.errorDescription ?: "The OP refused the request")
        }

        val tokenEndpoint = provider.metadata.tokenEndpoint
        if (!isHttpsUrl(tokenEndpoint)) return federationFailure("invalid_provider_metadata", "The OP token endpoint must be an https URL")
        val assertion = signer.clientAssertion(rp, provider.entityIdentifier, now, ASSERTION_LIFETIME_SECONDS)
        if (assertion.isErr) return Err(assertion.error)
        val tokens = redeem(
            tokenEndpoint,
            mapOf(
                "grant_type" to "authorization_code",
                "code" to code,
                "redirect_uri" to transaction.redirectUri,
                "code_verifier" to transaction.codeVerifier,
                "client_id" to rp.entityIdentifier,
                "client_assertion_type" to CLIENT_ASSERTION_TYPE_JWT_BEARER,
                "client_assertion" to assertion.value,
            ),
        )
        if (tokens.isErr) return Err(tokens.error)
        val idToken = tokens.value.idToken ?: return federationFailure("invalid_id_token", "The token response has no id_token")

        val validated = validateIdTokenCommand.execute(
            ValidateIdTokenArgs(
                idToken = idToken,
                options = IdTokenValidationOptions(
                    expectedIssuer = provider.entityIdentifier,
                    expectedAudience = rp.entityIdentifier,
                    expectedNonce = transaction.nonce,
                    accessToken = tokens.value.accessToken,
                    allowedAlgorithms = listOf(rp.idTokenSignedResponseAlg),
                    trustedJwks = JwkSet(provider.signingKeys.toTypedArray()),
                ),
            ),
        )
        if (validated.isErr) return Err(validated.error)
        val claims = validated.value.payload
        if (claims.iss != provider.entityIdentifier) return federationFailure("invalid_id_token", "ID Token iss is not the OP Entity Identifier")
        if (rp.entityIdentifier !in claims.aud) return federationFailure("invalid_id_token", "ID Token aud does not contain the RP")
        if (claims.aud.size > 1 && claims.azp != rp.entityIdentifier) {
            return federationFailure("invalid_id_token", "ID Token with several audiences must name the RP in azp")
        }
        if (claims.nonce != transaction.nonce) return federationFailure("invalid_id_token", "ID Token nonce does not match the request")

        return Ok(
            FederatedAuthenticationResult(
                accessToken = tokens.value.accessToken,
                tokenType = tokens.value.tokenType,
                refreshToken = tokens.value.refreshToken,
                idToken = idToken,
                idTokenClaims = claims,
                tokenResponse = tokens.value,
                providerEntityIdentifier = provider.entityIdentifier,
                trustAnchor = provider.trustAnchor,
            ),
        )
    }

    private suspend fun redeem(endpoint: String, form: Map<String, String>): IdkResult<TokenResponse, IdkError> {
        val client = httpClientFactory.createClient(HttpClientOptions(engine = null, enableContentNegotiation = false))
        val (status, body) = try {
            val response = client.post(endpoint) {
                header(HttpHeaders.ContentType, ContentType.Application.FormUrlEncoded.toString())
                header(HttpHeaders.Accept, ContentType.Application.Json.toString())
                setBody(encodeQueryParameters(form))
            }
            response.status to response.bodyAsText()
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (expected: Exception) {
            return federationFailure("temporarily_unavailable", "Token request to $endpoint failed: ${expected.message}")
        } finally {
            client.close()
        }
        if (!status.isSuccess()) {
            val json = runCatching { federatedRpJson.parseToJsonElement(body).jsonObject }.getOrNull()
            return federationFailure(
                json?.text("error") ?: "invalid_grant",
                json?.text("error_description") ?: "Token endpoint answered HTTP ${status.value}",
            )
        }
        return try {
            Ok(federatedRpJson.decodeFromString(TokenResponse.serializer(), body))
        } catch (expected: Exception) {
            federationFailure("invalid_response", "The token response is not a valid token response: ${expected.message}")
        }
    }

    private companion object {
        const val ASSERTION_LIFETIME_SECONDS = 60L
    }
}
