/*
 * Copyright 2023-2026 Sphereon International B.V.
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

package com.sphereon.oauth2.server.authorization.impl.command.oidc

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.encodeToBase64Url
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.service.StringResult
import com.sphereon.core.api.service.TypedServiceCommandAdapter
import com.sphereon.crypto.core.generic.hash
import com.sphereon.crypto.jose.jws.JwsIdentifierMode
import com.sphereon.crypto.jose.jws.JwtService
import com.sphereon.crypto.jose.jws.command.CreateJwsArgs
import com.sphereon.crypto.jose.jws.command.CreateJwsOpts
import com.sphereon.di.session.SessionScope
import com.sphereon.oauth2.common.config.OAuth2ServersConfigProvider
import com.sphereon.oauth2.common.config.OAuth2ServerInstanceIdProvider
import com.sphereon.oauth2.common.validation.jwsAlgToDigest
import com.sphereon.oauth2.server.authorization.command.CreateIdTokenArgs
import com.sphereon.oauth2.server.authorization.command.CreateIdTokenCommand
import com.sphereon.oauth2.server.authorization.error.AuthorizationServerError
import com.sphereon.oauth2.server.authorization.impl.command.asSigningProtectedHeader
import com.sphereon.oauth2.server.authorization.impl.command.discovery.keyAlgorithmToJwsAlg
import com.sphereon.oauth2.server.authorization.impl.command.putClaims
import com.sphereon.oauth2.server.authorization.provider.SessionParticipationRecorder
import com.sphereon.oauth2.server.authorization.signing.AsServerSigningIdentifierResolver
import com.sphereon.oauth2.server.authorization.signing.AsSigningRequirement
import com.sphereon.oauth2.server.authorization.signing.AsServerJwsSigner
import com.sphereon.oauth2.server.authorization.signing.CapturedAsServerConfig
import com.sphereon.oauth2.server.authorization.storage.ClientRegistry
import com.sphereon.oauth2.server.authorization.storage.OidcLoginSessionIdProvider
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.Named
import dev.zacsweers.metro.SingleIn
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlin.experimental.ExperimentalObjCName
import kotlin.native.ObjCName
import kotlin.time.Clock

import dev.zacsweers.metro.ExposeImplBinding
/**
 * Implementation of CreateIdTokenCommand
 *
 * Builds and signs an OpenID Connect ID Token JWT.
 *
 * Computes at_hash: SHA-256 of access token ASCII bytes, take left 128 bits, base64url encode.
 * Computes c_hash: same algorithm but for authorization code.
 */
@Inject
@SingleIn(SessionScope::class)
@OptIn(ExperimentalObjCName::class)
@ObjCName("CreateIdTokenCommandImpl", exact = true)
@ExposeImplBinding
class CreateIdTokenCommandImpl(
    execution: SessionExecution,
    private val jwtService: JwtService,
    private val configProvider: OAuth2ServersConfigProvider,
    private val asInstanceIdProvider: OAuth2ServerInstanceIdProvider,
    private val signingIdentifierResolver: AsServerSigningIdentifierResolver,
    private val clientRegistry: ClientRegistry,
    private val sessionParticipationRecorders: Set<SessionParticipationRecorder>,
    private val loginSessionIdProvider: OidcLoginSessionIdProvider,
    private val asServerJwsSigner: AsServerJwsSigner =
        AsServerJwsSigner { _, args -> jwtService.createJwsCompact(args) },
) : TypedServiceCommandAdapter<CreateIdTokenArgs, StringResult, IdkError>(
        commandId = CreateIdTokenCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<CreateIdTokenArgs>(),
        outputTypeToken = typeToken<StringResult>(),
    ),
    CreateIdTokenCommand {
    override val commandId: String get() = CreateIdTokenCommand.COMMAND_ID

    override suspend fun supports(args: Any): Boolean = args is CreateIdTokenArgs

    override suspend fun doExecute(
        args: CreateIdTokenArgs,
        applyDuring: (CreateIdTokenArgs) -> CreateIdTokenArgs,
    ): IdkResult<StringResult, IdkError> {
        val applied = applyDuring(args)
        return executeInternal(applied).map { StringResult(it) }.mapError { IdkError.fromDTO(it) }
    }

    private suspend fun executeInternal(args: CreateIdTokenArgs): IdkResult<String, AuthorizationServerError> {
        val root = configProvider.getConfig()
        val captured =
            try {
                CapturedAsServerConfig.select(root, asInstanceIdProvider.currentAsInstanceId())
            } catch (expected: IllegalArgumentException) {
                log.error("OAuth2 token issuance failed command=$commandId stage=server-selection error_type=IllegalArgumentException")
                return Err(AuthorizationServerError.ServerError(details = expected.message ?: "Invalid authorization server selection"))
            } catch (expected: IllegalStateException) {
                log.error("OAuth2 token issuance failed command=$commandId stage=server-selection error_type=IllegalStateException")
                return Err(AuthorizationServerError.ServerError(details = expected.message ?: "Authorization server selection failed"))
            }
        val config = captured.server
            ?: return Err(AuthorizationServerError.ServerError(details = "No hosted authorization server is configured"))
        val clientResult = clientRegistry.getClient(args.clientId)
        if (clientResult.isErr) {
            return Err(clientResult.error)
        }
        val client = clientResult.value ?: return Err(AuthorizationServerError.ClientNotFound(args.clientId))
        val requestedAlg = client.idTokenSignedResponseAlg?.trim()?.takeIf { it.isNotEmpty() }
        if (requestedAlg != null) {
            if (requestedAlg.equals("none", ignoreCase = true)) {
                return Err(AuthorizationServerError.ServerError(details = "Client '${args.clientId}' requests forbidden ID-token alg 'none'"))
            }
            val advertised = config.idTokenSigningAlgValuesSupported
            if (advertised != null && advertised.none { it.equals(requestedAlg, ignoreCase = true) }) {
                return Err(
                    AuthorizationServerError.ServerError(
                        details = "Client '${args.clientId}' requests ID-token alg '$requestedAlg', which this server does not advertise",
                    ),
                )
            }
        }
        val serverIdentifier =
            try {
                signingIdentifierResolver.selectSigning(captured, AsSigningRequirement.REQUIRED, requestedAlg).identifier
            } catch (cancelled: kotlinx.coroutines.CancellationException) {
                throw cancelled
            } catch (expected: Exception) {
                return Err(
                    AuthorizationServerError.ServerError(
                        details = "Cannot create ID token for client '${args.clientId}': ${expected.message}",
                        exception = expected,
                    ),
                )
            }
        if (serverIdentifier == null) {
            return Err(
                AuthorizationServerError.ServerError(
                    details = "Cannot create ID token: server signing key not configured",
                    exception = null,
                ),
            )
        }

        val issuerUrl =
            args.baseUrlOverride?.takeIf { it.isNotBlank() }
                ?: config.issuer
                ?: return Err(
                    AuthorizationServerError.ServerError(
                        details =
                            "OAuth2 server has no issuer configured and no request-time baseUrl override; " +
                                "set oauth2.servers.<id>.issuer or ensure the request carries Host + X-Forwarded-Proto headers",
                    ),
                )

        val now = Clock.System.now()
        val expiresAt = now.epochSeconds + config.idTokenLifetimeSeconds

        // The selected public descriptor carries the JOSE algorithm; do not fetch private material.
        val idTokenSigningAlg = try {
            val selectedAlgorithm = serverIdentifier.identifier.signatureAlgorithm
                ?: return Err(AuthorizationServerError.ServerError(details = "Selected ID-token signing key has no algorithm"))
            keyAlgorithmToJwsAlg(selectedAlgorithm)
        } catch (expected: IllegalStateException) {
            return Err(AuthorizationServerError.ServerError(details = expected.message ?: "Unsupported ID-token signing algorithm"))
        }

        if (requestedAlg != null && requestedAlg != idTokenSigningAlg) {
            return Err(AuthorizationServerError.ServerError(
                details = "Selected ID-token signing algorithm '$idTokenSigningAlg' does not match the client's requested '$requestedAlg'",
            ))
        }

        // OIDC Back-Channel Logout 1.0 §4.1: emit `sid` so RPs can correlate logout_token.sid
        // back to a local session. We prefer the cookie-derived OIDC login session id (the
        // value the end-session orchestrator looks up when the RP later passes id_token_hint),
        // falling back to args.sessionId (the pending-authorization session id) when the
        // cookie isn't on the request (e.g. federated grants that don't write the AS-side
        // cookie). The same value is later handed to [sessionParticipationRecorder] so the
        // RP-binding map keys match the `sid` the RP saw in its id_token.
        val sidClaim: String? = loginSessionIdProvider.currentLoginSessionId() ?: args.sessionId

        val payload =
            buildJsonObject {
                put("iss", issuerUrl)
                put("sub", args.subject)
                put("aud", args.clientId)
                put("exp", expiresAt)
                put("iat", now.epochSeconds)
                sidClaim?.let { put("sid", it) }

                args.nonce?.let { put("nonce", it) }
                args.authTime?.let { put("auth_time", it) }
                args.acr?.let { put("acr", it) }
                args.amr?.let { amrList ->
                    put("amr", buildJsonArray { amrList.forEach { add(JsonPrimitive(it)) } })
                }

                // at_hash / c_hash per OIDC Core §3.1.3.6: hash algorithm matches the ID token
                // signing alg (RS/ES/PS/HS 256/384/512 → SHA-256/-384/-512). The signing alg
                // is derived from the selected KMS key so the digest matches the JWS header
                // `alg` `PrepareJwsCommandImpl` will write.
                args.accessToken?.let { token ->
                    computeTokenHash(token, idTokenSigningAlg)?.let { put("at_hash", it) }
                }
                args.authorizationCode?.let { code ->
                    computeTokenHash(code, idTokenSigningAlg)?.let { put("c_hash", it) }
                }

                // OIDC Core §5.4: "The Claims requested by the profile, email, address, and
                // phone scope values are returned from the UserInfo Endpoint … when a
                // response_type value is used that results in an Access Token being issued.
                // However, when no Access Token is issued (which is the case for the
                // response_type value id_token), the resulting Claims are returned in the
                // ID Token." So in code/hybrid flows we keep scope-derived user claims
                // out of the id_token by default (they go to /userinfo); the OIDC Basic
                // conformance suite's `EnsureIdTokenDoesNotContainNonRequestedClaims`
                // warns when they leak in. Pure id_token flows always embed them.
                //
                // The deployment opt-in `embedUserinfoClaimsInIdToken` overrides this
                // separation — when true, the id_token always carries every projected
                // user claim, useful for RPs that consume only the id_token and never
                // call /userinfo (e.g. Auth.js v5 default behaviour). Deviates from
                // §5.4 — operators turn it off for OIDC Basic OP conformance runs.
                //
                // `additionalClaims` is reserved for explicit `claims` request-parameter
                // entries (OIDC Core §5.5) and stays unconditional — by definition the RP
                // asked for those in the id_token.
                if (args.accessToken == null || config.embedUserinfoClaimsInIdToken) {
                    putClaims(args.userClaims)
                }
                putClaims(args.additionalClaims)
            }

        val header = asSigningProtectedHeader("JWT", serverIdentifier)

        return try {
            val jwsArgs =
                CreateJwsArgs(
                    issuer = serverIdentifier,
                    payload = payload.toString(),
                    mode = JwsIdentifierMode.KID,
                    opts =
                        CreateJwsOpts(
                            protectedHeader = header,
                            noIssPayloadUpdate = true,
                        ),
                )

            asServerJwsSigner
                .sign(captured, jwsArgs)
                .map { it.jwt }
                .mapError { error ->
                    log.error("OAuth2 token issuance failed command=$commandId stage=id-token-signing idk_code=${error.code}")
                    AuthorizationServerError.ServerError(
                        details = "Failed to sign ID token: ${error.message.defaultMessage}",
                        exception = error.exception,
                    )
                }.also { result ->
                    // Record RP participation post-signing so OIDC Back-Channel Logout
                    // §2.4 / Front-Channel Logout 1.0 §3 can target the right recipients.
                    // Best-effort: a recorder failure here must not fail token issuance —
                    // it degrades logout precision (fall back to notifying every RP), never
                    // blocks auth.
                    //
                    // Use the same `sid` value the id_token carried so the
                    // [SessionParticipationRecorder] can map RPs into the cookie-keyed
                    // login session record the end-session orchestrator looks up.
                    val recordedSid = sidClaim
                    if (result.isOk && recordedSid != null) {
                        for (recorder in sessionParticipationRecorders) {
                            val recorded =
                                recorder.recordRpParticipation(
                                    sessionId = recordedSid,
                                    clientId = args.clientId,
                                )
                            if (!recorded.isOk) {
                                execution.log.warn(
                                    "SessionParticipationRecorder ${recorder::class.simpleName} failed for " +
                                        "session=$recordedSid client=${args.clientId}: " +
                                        "${recorded.error.message.defaultMessage}, back-channel logout precision " +
                                        "for this recorder degrades to all-registered-RPs fallback",
                                )
                            }
                        }
                    }
                }
        } catch (cancelled: kotlinx.coroutines.CancellationException) {
            throw cancelled
        } catch (expected: Exception) {
            log.error("OAuth2 token issuance failed command=$commandId stage=id-token-mint error_type=${expected::class.simpleName}")
            Err(
                AuthorizationServerError.ServerError(
                    details = "ID token creation failed: ${expected.message}",
                    exception = expected,
                ),
            )
        }
    }

    /**
     * Compute `at_hash` / `c_hash` per OpenID Connect Core §3.1.3.6: take the JWS digest matching
     * [jwsAlg] (256/384/512), hash the ASCII bytes of [input], take the left half of the digest,
     * base64url encode without padding.
     *
     * Returns `null` (omits the hash claim) if [jwsAlg] is unknown or the digest routine throws —
     * a missing hash claim is preferable to emitting a wrong value that would fail RP validation.
     */
    private fun computeTokenHash(
        input: String,
        jwsAlg: String,
    ): String? {
        val digestAlg = jwsAlgToDigest(jwsAlg)
        if (digestAlg == null) {
            execution.log.warn("No digest mapping for JWS alg '$jwsAlg'; omitting at_hash/c_hash")
            return null
        }
        return try {
            val bytes = input.encodeToByteArray()
            val hashBytes = hash(bytes, digestAlg)
            val leftHalf = hashBytes.copyOfRange(0, hashBytes.size / 2)
            leftHalf.encodeToBase64Url()
        } catch (expected: Exception) {
            execution.log.debug("Failed to compute token hash with alg $jwsAlg: ${expected.message}")
            null
        }
    }

}
