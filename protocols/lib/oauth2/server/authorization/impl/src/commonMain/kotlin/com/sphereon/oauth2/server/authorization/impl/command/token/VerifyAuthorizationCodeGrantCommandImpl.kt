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

package com.sphereon.oauth2.server.authorization.impl.command.token

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.encodeToBase64Url
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.security.ConstantTime
import com.sphereon.core.api.service.TypedServiceCommandAdapter
import com.sphereon.crypto.core.generic.DigestAlg
import com.sphereon.crypto.core.generic.hash
import com.sphereon.di.session.SessionScope
import com.sphereon.oauth2.common.config.OAuth2ServersConfigProvider
import com.sphereon.oauth2.common.config.isRequired
import com.sphereon.oauth2.common.model.PkceMethod
import com.sphereon.oauth2.common.model.ClientAuthenticationMethod
import com.sphereon.oauth2.common.model.GrantType
import com.sphereon.oauth2.server.authorization.command.VerifiedAuthorizationCodeGrant
import com.sphereon.oauth2.server.authorization.command.VerifiedClientAuthorization
import com.sphereon.oauth2.server.authorization.command.VerifyAuthorizationCodeGrantArgs
import com.sphereon.oauth2.server.authorization.command.VerifyAuthorizationCodeGrantCommand
import com.sphereon.oauth2.server.authorization.error.AuthorizationServerError
import com.sphereon.oauth2.server.authorization.impl.command.clientauth.toVerifiedClientAuthorization
import com.sphereon.oauth2.server.authorization.storage.AuthorizationCodeStorage
import com.sphereon.oauth2.server.authorization.storage.ClientRegistry
import com.sphereon.oauth2.server.authorization.model.ClientType
import com.sphereon.oauth2.server.authorization.impl.time.OAUTH2_ARTIFACT_CLOCK
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.Named
import dev.zacsweers.metro.SingleIn
import kotlin.experimental.ExperimentalObjCName
import kotlin.native.ObjCName
import kotlin.time.Clock

import dev.zacsweers.metro.ExposeImplBinding
private const val MIN_PKCE_LENGTH = 43
private const val MAX_PKCE_LENGTH = 128

/**
 * Implementation of VerifyAuthorizationCodeGrantCommand
 *
 * Verifies authorization_code grant requests according to RFC 6749 Section 4.1.3
 * with PKCE support (RFC 7636).
 *
 * Verification steps:
 * 1. Retrieve and consume authorization code (atomic operation)
 * 2. Verify code is not expired
 * 3. Verify client_id matches
 * 4. Verify redirect_uri matches (if present in original request)
 * 5. Verify PKCE code_verifier (if PKCE was used)
 * 6. Return verified grant data
 *
 * Security considerations:
 * - Authorization codes MUST be single-use (RFC 6749 Section 10.5)
 * - Codes MUST be short-lived (typically 10 minutes max)
 * - PKCE MUST be used for public clients (RFC 8252)
 * - DPoP binding is preserved if present
 */
@Inject
@SingleIn(SessionScope::class)
@OptIn(ExperimentalObjCName::class)
@ObjCName("VerifyAuthorizationCodeGrantCommandImpl", exact = true)
@ExposeImplBinding
class VerifyAuthorizationCodeGrantCommandImpl(
    execution: SessionExecution,
    private val authorizationCodeStorage: AuthorizationCodeStorage,
    private val tokenStorage: com.sphereon.oauth2.server.authorization.storage.TokenStorage,
    private val clientRegistry: ClientRegistry,
    private val configProvider: OAuth2ServersConfigProvider,
    @param:Named(OAUTH2_ARTIFACT_CLOCK) private val artifactClock: Clock = Clock.System,
) : TypedServiceCommandAdapter<VerifyAuthorizationCodeGrantArgs, VerifiedAuthorizationCodeGrant, IdkError>(
        commandId = VerifyAuthorizationCodeGrantCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<VerifyAuthorizationCodeGrantArgs>(),
        outputTypeToken = typeToken<VerifiedAuthorizationCodeGrant>(),
    ),
    VerifyAuthorizationCodeGrantCommand {
    override val commandId: String get() = VerifyAuthorizationCodeGrantCommand.COMMAND_ID

    override suspend fun supports(args: Any): Boolean = args is VerifyAuthorizationCodeGrantArgs

    override suspend fun doExecute(
        args: VerifyAuthorizationCodeGrantArgs,
        applyDuring: (VerifyAuthorizationCodeGrantArgs) -> VerifyAuthorizationCodeGrantArgs,
    ): IdkResult<VerifiedAuthorizationCodeGrant, IdkError> {
        val applied = applyDuring(args)
        return executeInternal(
            applied.code,
            applied.redirectUri,
            applied.clientId,
            applied.codeVerifier,
            applied.requestedResource,
            null,
        ).mapError { IdkError.fromDTO(it) }
    }

    internal suspend fun verifyWithTrustedClientAuthorization(
        args: VerifyAuthorizationCodeGrantArgs,
        clientAuthorization: VerifiedClientAuthorization,
    ): IdkResult<VerifiedAuthorizationCodeGrant, IdkError> =
        executeInternal(
            args.code,
            args.redirectUri,
            args.clientId,
            args.codeVerifier,
            args.requestedResource,
            clientAuthorization,
        ).mapError { IdkError.fromDTO(it) }

    private suspend fun executeInternal(
        code: String,
        redirectUri: String,
        clientId: String,
        codeVerifier: String?,
        requestedResource: List<String>,
        clientAuthorization: VerifiedClientAuthorization?,
    ): IdkResult<VerifiedAuthorizationCodeGrant, AuthorizationServerError> {
        // Retrieve and consume authorization code (atomic operation)
        // This prevents replay attacks by ensuring the code can only be used once
        val codeData =
            authorizationCodeStorage.consumeAuthorizationCode(code).getOrElse { error ->
                execution.log.error("Authorization code verification failed command=$commandId stage=code-storage")
                return Err(
                    AuthorizationServerError.ServerError(
                        details = "Failed to retrieve authorization code: ${error.details}",
                        exception = null,
                    ),
                )
            }

        // Check if code was found
        if (codeData == null) {
            // RFC 6749 §10.5: "If an authorization code is used more than once, the
            // authorization server MUST deny the request and SHOULD revoke (when possible)
            // all tokens previously issued based on that authorization code." `consume…`
            // returns null in two cases: the code was never stored / has expired off, OR
            // it was already consumed. `findAuthorizationCode` distinguishes them — when an
            // entry exists with `used = true`, this is a replay; revoke the tokens minted on
            // the first redemption so a downstream resource-server introspection returns
            // `active = false` and rejects any in-flight access. Best-effort: a revoke
            // failure here is logged but does not change the InvalidGrant we return.
            val storedCode = authorizationCodeStorage.findAuthorizationCode(code).getOrElse { null }
            logTokenRefusal(execution.log, "Authorization code verification refused command=$commandId stage=code-lookup stored=${storedCode != null} used=${storedCode?.used == true}")
            storedCode?.let { stored ->
                if (stored.used) {
                    stored.issuedAccessToken?.let { tokenStorage.revokeAccessToken(it) }
                    stored.issuedRefreshToken?.let { tokenStorage.revokeRefreshToken(it) }
                }
            }
            val matchingAdmission = storedCode?.let { it.clientId == clientId && it.admittedClient?.clientId == clientId } == true
            val registeredClient = clientRegistry.getClient(clientId).getOrElse { error ->
                return Err(AuthorizationServerError.ServerError(details = "Failed to retrieve client registration: $error"))
            }
            if (!matchingAdmission && registeredClient == null) {
                return Err(AuthorizationServerError.InvalidClient(details = "Unknown client '$clientId'"))
            }
            return Err(
                AuthorizationServerError.InvalidGrant(
                    details = "Invalid or expired authorization code",
                    exception = null,
                ),
            )
        }

        // Verify code is not expired
        val now = artifactClock.now()
        if (codeData.expiresAt < now) {
            logTokenRefusal(execution.log, "Authorization code verification refused command=$commandId stage=code-expired")
            return Err(
                AuthorizationServerError.InvalidGrant(
                    details = "Authorization code has expired",
                    exception = null,
                ),
            )
        }

        // Verify client_id matches
        if (codeData.clientId != clientId) {
            logTokenRefusal(execution.log, "Authorization code verification refused command=$commandId stage=client-binding")
            return Err(
                AuthorizationServerError.InvalidGrant(
                    details = "Authorization code was issued to a different client",
                    exception = null,
                ),
            )
        }

        val admittedClient = codeData.admittedClient
        if (admittedClient != null) {
            if (admittedClient.clientId != clientId ||
                admittedClient.clientType != ClientType.PUBLIC ||
                admittedClient.tokenEndpointAuthMethod != ClientAuthenticationMethod.NONE ||
                GrantType.AUTHORIZATION_CODE !in admittedClient.grantTypes ||
                !admittedClient.requirePkce
            ) {
                logTokenRefusal(execution.log, "Authorization code verification refused command=$commandId stage=client-admission")
                return Err(AuthorizationServerError.InvalidClient(details = "Authorization code admission does not match this client"))
            }
            if (codeData.codeChallenge.isNullOrBlank() || codeData.codeChallengeMethod != PkceMethod.S256) {
                logTokenRefusal(execution.log, "Authorization code verification refused command=$commandId stage=admitted-pkce-method")
                return Err(AuthorizationServerError.InvalidGrant(details = "Admitted wallet authorization code requires PKCE S256"))
            }
        } else if (clientAuthorization == null) {
            val registeredClient = clientRegistry.getClient(clientId).getOrElse { error ->
                return Err(AuthorizationServerError.ServerError(details = "Failed to retrieve client registration: $error"))
            }
            if (registeredClient == null ||
                registeredClient.clientType != ClientType.PUBLIC ||
                registeredClient.tokenEndpointAuthMethod != ClientAuthenticationMethod.NONE
            ) {
                return Err(AuthorizationServerError.InvalidClient(details = "Client authentication is required"))
            }
        }

        // RFC 8707: a token request may repeat the resource indicator only when it is the
        // exact set bound to the authorization request. Omitting it derives the bound resource.
        if (requestedResource.any { !isSecureResourceIndicator(it) }) {
            return Err(AuthorizationServerError.InvalidTarget(resource = requestedResource.first(), reason = "resource must be a secure absolute URI without a fragment"))
        }
        if (requestedResource.isNotEmpty() && requestedResource != codeData.resource) {
            logTokenRefusal(execution.log, "Authorization code verification refused command=$commandId stage=resource-binding")
            return Err(AuthorizationServerError.InvalidGrant(details = "resource does not match authorization request"))
        }

        // Verify redirect_uri matches (if present in original request)
        // RFC 6749 Section 4.1.3: redirect_uri REQUIRED if included in authorization request
        if (codeData.redirectUri.isNotBlank()) {
            if (redirectUri.isBlank()) {
                return Err(
                    AuthorizationServerError.InvalidRequest(
                        details = "Missing required parameter: redirect_uri",
                        exception = null,
                    ),
                )
            }
            // Constant-time compare. Redirect URIs are not secrets, but matching the same
            // discipline as the PKCE compare below means a future grep audit can rely on
            // every `redirect_uri` comparison going through ConstantTime — no exceptions to
            // explain in the code review.
            if (!ConstantTime.equalsCT(codeData.redirectUri, redirectUri)) {
                logTokenRefusal(execution.log, "Authorization code verification refused command=$commandId stage=redirect-binding")
                return Err(
                    AuthorizationServerError.InvalidGrant(
                        details = "redirect_uri does not match authorization request",
                        exception = null,
                    ),
                )
            }
        }

        // Verify PKCE if code_challenge was present (RFC 7636 §4.6). PKCE failures at /token
        // — missing/short/malformed verifier, computed challenge mismatch — are all `invalid_grant`
        // per RFC 7636, NOT `invalid_request`. The conformance suite checks the wire `error`
        // field byte-equal to `invalid_grant` (FAPI2-SP §5.3.2.1, RFC7636-4.6).
        val storedCodeChallenge = codeData.codeChallenge
        if (storedCodeChallenge != null) {
            if (codeVerifier.isNullOrBlank()) {
                logTokenRefusal(execution.log, "Authorization code verification refused command=$commandId stage=pkce-missing")
                return Err(
                    AuthorizationServerError.InvalidGrant(
                        details = "Missing required parameter: code_verifier (PKCE required)",
                        exception = null,
                    ),
                )
            }

            // Verify code_verifier format (RFC 7636 Section 4.1)
            // Must be 43-128 characters, A-Z, a-z, 0-9, -, ., _, ~
            if (codeVerifier.length !in MIN_PKCE_LENGTH..MAX_PKCE_LENGTH) {
                logTokenRefusal(execution.log, "Authorization code verification refused command=$commandId stage=pkce-format")
                return Err(
                    AuthorizationServerError.InvalidGrant(
                        details = "code_verifier must be 43-128 characters",
                        exception = null,
                    ),
                )
            }

            // Compute challenge from verifier
            val computedChallenge =
                when (codeData.codeChallengeMethod ?: PkceMethod.S256) {
                    PkceMethod.PLAIN -> {
                        codeVerifier
                    }

                    PkceMethod.S256 -> {
                        // BASE64URL(SHA256(ASCII(code_verifier)))
                        hash(codeVerifier.encodeToByteArray(), DigestAlg.SHA256).encodeToBase64Url()
                    }
                }

            // Verify challenge matches. RFC 7636 §4.6 — `code_challenge` is derived from a
            // secret known only to the legitimate client; a non-CT compare leaks "did you
            // hit a valid prefix?" timing that, combined with retries, lets an attacker
            // recover the challenge byte-by-byte.
            if (!ConstantTime.equalsCT(computedChallenge, storedCodeChallenge)) {
                logTokenRefusal(execution.log, "Authorization code verification refused command=$commandId stage=pkce-binding")
                return Err(
                    AuthorizationServerError.InvalidGrant(
                        details = "PKCE verification failed: code_verifier does not match code_challenge",
                        exception = null,
                    ),
                )
            }
        } else if (admittedClient != null) {
            logTokenRefusal(execution.log, "Authorization code verification refused command=$commandId stage=admitted-pkce-missing")
            return Err(AuthorizationServerError.InvalidGrant(details = "Admitted wallet authorization code requires PKCE"))
        } else {
            // No PKCE was used - check if it's required for this client
            if (clientAuthorization != null && clientAuthorization.clientId != clientId) {
                return Err(AuthorizationServerError.InvalidClient(details = "Authenticated client does not match requested client"))
            }
            val client =
                clientAuthorization
                    ?: clientRegistry
                        .getClient(clientId)
                        .getOrElse { error ->
                            return Err(
                                AuthorizationServerError.ServerError(
                                    details = "Failed to retrieve client registration: $error",
                                    exception = null,
                                ),
                            )
                        }?.toVerifiedClientAuthorization()

            if (client == null) {
                return Err(
                    AuthorizationServerError.InvalidClient(
                        details = "Client not found",
                        exception = null,
                    ),
                )
            }

            // Check server-level PKCE requirement from config
            val serverPkceRequired = configProvider.serverConfig.pkce.isRequired

            // RFC 8252: Public clients MUST use PKCE
            if (client.requirePkce || serverPkceRequired) {
                return Err(
                    AuthorizationServerError.InvalidRequest(
                        details = "PKCE is required for this client",
                        exception = null,
                    ),
                )
            }
        }

        // Return verified grant
        return Ok(
            VerifiedAuthorizationCodeGrant(
                codeData = codeData,
                subject = codeData.subject,
                clientId = codeData.clientId,
                scope = codeData.scope,
                resource = codeData.resource,
                defaultAccessTokenAudience = codeData.defaultAccessTokenAudience,
                dpopJkt = codeData.dpopJkt,
                userClaims = codeData.userClaims,
                additionalData = codeData.additionalData,
            ),
        )
    }
}

private fun isSecureResourceIndicator(value: String): Boolean =
    SECURE_RESOURCE_URI.matches(value)

private val SECURE_RESOURCE_URI = Regex("^https://[a-z0-9.-]+(?::[0-9]{1,5})?(?:/[^#\\s]*)?$", RegexOption.IGNORE_CASE)
