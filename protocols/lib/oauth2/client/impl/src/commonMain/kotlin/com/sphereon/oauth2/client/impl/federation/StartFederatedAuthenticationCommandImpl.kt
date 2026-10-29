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

import com.sphereon.core.api.decodeFromBase64Url
import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.random.SecureRandom
import com.sphereon.core.api.service.TypedServiceCommandAdapter
import com.sphereon.crypto.jose.jws.JwtService
import com.sphereon.di.session.SessionScope
import com.sphereon.ktor.http.client.provider.HttpClientFactory
import com.sphereon.ktor.http.client.provider.HttpClientOptions
import com.sphereon.oauth2.client.command.CreatePkceArgs
import com.sphereon.oauth2.client.command.CreatePkceCommand
import com.sphereon.oauth2.client.command.FederatedAuthenticationRequest
import com.sphereon.oauth2.client.command.FederatedAuthenticationRequestTransport
import com.sphereon.oauth2.client.command.FederatedAuthenticationTransaction
import com.sphereon.oauth2.client.command.StartFederatedAuthenticationArgs
import com.sphereon.oauth2.client.command.StartFederatedAuthenticationCommand
import com.sphereon.oauth2.client.util.buildUrl
import com.sphereon.oauth2.client.util.encodeQueryParameters
import com.sphereon.oauth2.common.model.PkceMethod
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
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import kotlin.time.Clock

/**
 * Automatic Registration Authentication Request (OpenID Federation for OpenID Connect 1.1 §12.1.1).
 *
 * The Request Object carries every request parameter. With PAR it is pushed together with a `private_key_jwt` client
 * assertion whose sole audience is the OP's Entity Identifier (§12.1.1.2), and the user agent only gets `client_id`
 * and `request_uri`. Without PAR it is passed by value, with `response_type`, `client_id` and `scope` repeated as
 * OAuth 2.0 parameters as OpenID Connect Core 1.0 §6.1 requires.
 */
@Inject
@SingleIn(SessionScope::class)
@ExposeImplBinding
class StartFederatedAuthenticationCommandImpl(
    execution: SessionExecution,
    private val createPkceCommand: CreatePkceCommand,
    private val httpClientFactory: HttpClientFactory,
    jwtService: JwtService,
    secureRandom: SecureRandom,
) : TypedServiceCommandAdapter<StartFederatedAuthenticationArgs, FederatedAuthenticationRequest, IdkError>(
        commandId = StartFederatedAuthenticationCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<StartFederatedAuthenticationArgs>(),
        outputTypeToken = typeToken<FederatedAuthenticationRequest>(),
    ),
    StartFederatedAuthenticationCommand {
    override val commandId: String get() = StartFederatedAuthenticationCommand.COMMAND_ID

    private val signer = FederatedRpJwtSigner(jwtService, secureRandom)

    override suspend fun supports(args: Any): Boolean = args is StartFederatedAuthenticationArgs

    override suspend fun doExecute(
        args: StartFederatedAuthenticationArgs,
        applyDuring: (StartFederatedAuthenticationArgs) -> StartFederatedAuthenticationArgs,
    ): IdkResult<FederatedAuthenticationRequest, IdkError> {
        val applied = applyDuring(args)
        val provider = applied.provider
        val rp = applied.relyingParty
        val now = Clock.System.now().epochSeconds

        if (!isHttpsUrl(rp.entityIdentifier)) return federationFailure("invalid_request", "The RP Entity Identifier must be an https URL")
        if (applied.lifetimeSeconds !in 1..MAX_LIFETIME_SECONDS) {
            return federationFailure("invalid_request", "The Request Object lifetime must be between 1 and $MAX_LIFETIME_SECONDS seconds")
        }
        if (applied.scope.split(' ').none { it == "openid" }) return federationFailure("invalid_scope", "The scope must contain openid")
        providerProblem(provider, rp, now)?.let { return federationFailure("invalid_provider_metadata", it) }
        applied.trustChain?.let { chain ->
            rpTrustChainProblem(chain, rp.entityIdentifier, provider.trustAnchor)?.let { return federationFailure("invalid_request", it) }
        }

        val metadata = provider.metadata
        val parEndpoint = metadata.pushedAuthorizationRequestEndpoint
        val pushed = when (applied.transport) {
            FederatedAuthenticationRequestTransport.AUTO -> parEndpoint != null
            FederatedAuthenticationRequestTransport.PUSHED_AUTHORIZATION_REQUEST -> true
            FederatedAuthenticationRequestTransport.REQUEST_OBJECT -> false
        }
        if (pushed && parEndpoint == null) return federationFailure("invalid_provider_metadata", "The OP has no pushed_authorization_request_endpoint")
        if (pushed && !isHttpsUrl(parEndpoint!!)) return federationFailure("invalid_provider_metadata", "The OP PAR endpoint must be an https URL")
        if (!pushed && metadata.requirePushedAuthorizationRequests == true) {
            return federationFailure("invalid_request", "The OP requires Pushed Authorization Requests")
        }
        if (!pushed && metadata.requestParameterSupported == false) {
            return federationFailure("invalid_provider_metadata", "The OP does not accept the request parameter")
        }

        val pkce = createPkceCommand.execute(CreatePkceArgs(allowedMethods = listOf(PkceMethod.S256)))
        if (pkce.isErr) return Err(pkce.error)
        val state = signer.newToken()
        val nonce = signer.newToken()

        val requestObject = signer.sign(
            rp,
            buildJsonObject {
                put("typ", REQUEST_OBJECT_TYP)
                applied.trustChain?.let { chain -> put("trust_chain", JsonArray(chain.map { JsonPrimitive(it) })) }
            },
            buildJsonObject {
                // §12.1.1.1: aud is the OP's Entity Identifier only; iss and client_id are the RP's; no sub.
                put("iss", rp.entityIdentifier)
                put("aud", provider.entityIdentifier)
                put("client_id", rp.entityIdentifier)
                put("jti", signer.newToken())
                put("iat", now)
                put("exp", now + applied.lifetimeSeconds)
                put("response_type", "code")
                put("scope", applied.scope)
                put("redirect_uri", rp.redirectUri)
                put("state", state)
                put("nonce", nonce)
                put("code_challenge", pkce.value.codeChallenge)
                put("code_challenge_method", pkce.value.codeChallengeMethod.value)
                applied.loginHint?.let { put("login_hint", it) }
                applied.prompt?.let { put("prompt", it) }
                applied.acrValues?.let { put("acr_values", it) }
            },
        )
        if (requestObject.isErr) return Err(requestObject.error)

        val transaction = FederatedAuthenticationTransaction(
            providerEntityIdentifier = provider.entityIdentifier,
            clientId = rp.entityIdentifier,
            redirectUri = rp.redirectUri,
            state = state,
            nonce = nonce,
            codeVerifier = pkce.value.codeVerifier,
            pushed = pushed,
            createdAtEpochSeconds = now,
        )
        val authorizationEndpoint = requireNotNull(metadata.authorizationEndpoint)
        if (!pushed) {
            val url = buildUrl(
                authorizationEndpoint,
                mapOf(
                    "client_id" to rp.entityIdentifier,
                    "response_type" to "code",
                    "scope" to applied.scope,
                    "redirect_uri" to rp.redirectUri,
                    "request" to requestObject.value,
                ),
            )
            return Ok(FederatedAuthenticationRequest(authorizationUrl = url, transaction = transaction))
        }

        val assertion = signer.clientAssertion(rp, provider.entityIdentifier, now, applied.lifetimeSeconds)
        if (assertion.isErr) return Err(assertion.error)
        val requestUri = push(
            endpoint = parEndpoint!!,
            form = mapOf(
                "client_id" to rp.entityIdentifier,
                "request" to requestObject.value,
                "client_assertion_type" to CLIENT_ASSERTION_TYPE_JWT_BEARER,
                "client_assertion" to assertion.value,
            ),
        )
        if (requestUri.isErr) return Err(requestUri.error)
        val url = buildUrl(authorizationEndpoint, mapOf("client_id" to rp.entityIdentifier, "request_uri" to requestUri.value))
        return Ok(FederatedAuthenticationRequest(authorizationUrl = url, transaction = transaction, requestUri = requestUri.value))
    }

    /** RFC 9126 §2: the OP answers 201 with `request_uri` and `expires_in`; an error body is returned as is. */
    private suspend fun push(endpoint: String, form: Map<String, String>): IdkResult<String, IdkError> {
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
            return federationFailure("temporarily_unavailable", "Pushed Authorization Request to $endpoint failed: ${expected.message}")
        } finally {
            client.close()
        }
        val json = runCatching { federatedRpJson.parseToJsonElement(body).jsonObject }.getOrNull()
        if (!status.isSuccess()) {
            val error = json?.text("error") ?: "invalid_request"
            val description = json?.text("error_description") ?: "PAR endpoint answered HTTP ${status.value}"
            return federationFailure(error, description)
        }
        val requestUri = json?.text("request_uri")
            ?: return federationFailure("invalid_request", "PAR response has no request_uri")
        val expiresIn = (json["expires_in"] as? JsonPrimitive)?.content?.toLongOrNull()
        if (expiresIn == null || expiresIn <= 0) return federationFailure("invalid_request", "PAR response has no positive expires_in")
        return Ok(requestUri)
    }
}

/**
 * Why [chain] cannot be sent as the RP's `trust_chain`: it must start with the RP's own Entity Configuration and end
 * at the Trust Anchor the OP was resolved under, the one the RP and the OP have in common (OpenID Federation for
 * OpenID Connect 1.1 §12.1.1.1). The OP verifies every statement itself; this only keeps the RP from sending a chain
 * to a Trust Anchor it did not select.
 */
internal fun rpTrustChainProblem(chain: List<String>, rpEntityIdentifier: String, trustAnchor: String): String? {
    if (chain.isEmpty()) return "The trust_chain must not be empty"
    fun claims(jwt: String): kotlinx.serialization.json.JsonObject? = runCatching {
        val parts = jwt.split('.')
        require(parts.size == 3)
        kotlinx.serialization.json.Json.parseToJsonElement(parts[1].decodeFromBase64Url().decodeToString())
            as kotlinx.serialization.json.JsonObject
    }.getOrNull()
    fun kotlinx.serialization.json.JsonObject.claim(name: String): String? =
        (this[name] as? kotlinx.serialization.json.JsonPrimitive)?.takeIf { it.isString }?.content
    val first = claims(chain.first()) ?: return "The trust_chain statements must be JWTs"
    val last = claims(chain.last()) ?: return "The trust_chain statements must be JWTs"
    if (first.claim("iss") != rpEntityIdentifier || first.claim("sub") != rpEntityIdentifier) {
        return "The trust_chain must start with the RP's own Entity Configuration"
    }
    if (last.claim("iss") != trustAnchor) return "The trust_chain must end at the Trust Anchor '$trustAnchor' the OP was resolved under"
    return null
}
