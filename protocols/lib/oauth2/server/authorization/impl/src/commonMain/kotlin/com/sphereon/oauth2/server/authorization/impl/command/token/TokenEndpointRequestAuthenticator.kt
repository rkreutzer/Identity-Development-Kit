/*
 * © 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

package com.sphereon.oauth2.server.authorization.impl.command.token

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.encodeToBase64Url
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.log.SessionLogService
import com.sphereon.crypto.core.generic.DigestAlg
import com.sphereon.crypto.core.generic.hash
import com.sphereon.crypto.core.jose.generateJwkThumbprint
import com.sphereon.oauth2.common.command.VerifyDpopProofCommand
import com.sphereon.oauth2.common.config.OAuth2ServersConfigProvider
import com.sphereon.oauth2.common.model.ClientAuthenticationConfig
import com.sphereon.oauth2.common.model.ClientAuthenticationMethod
import com.sphereon.oauth2.common.model.GrantType
import com.sphereon.oauth2.common.model.VerifyDpopProofOptions
import com.sphereon.oauth2.server.authorization.command.ClientAuthenticationEndpoint
import com.sphereon.oauth2.server.authorization.command.ParseTokenRequestArgs
import com.sphereon.oauth2.server.authorization.command.ParseTokenRequestCommand
import com.sphereon.oauth2.server.authorization.command.TokenRequestData
import com.sphereon.oauth2.server.authorization.command.VerifiedClientAuthentication
import com.sphereon.oauth2.server.authorization.command.VerifiedClientAuthorization
import com.sphereon.oauth2.server.authorization.command.VerifyClientAuthenticationArgs
import com.sphereon.oauth2.server.authorization.command.VerifyClientAuthenticationCommand
import com.sphereon.oauth2.server.authorization.command.token.GrantContext
import com.sphereon.oauth2.server.authorization.command.token.HandleTokenRequestArgs
import com.sphereon.oauth2.server.authorization.dpop.DpopNonceManager
import com.sphereon.oauth2.server.authorization.dpop.DpopProofJtiCache
import com.sphereon.oauth2.server.authorization.error.AuthorizationServerError
import com.sphereon.oauth2.server.authorization.impl.command.TokenPathStage
import com.sphereon.oauth2.server.authorization.impl.command.TokenPathStageTimings
import com.sphereon.oauth2.server.authorization.impl.command.token.grant.errOf
import com.sphereon.oauth2.server.authorization.impl.command.token.grant.invalidDpopProof
import kotlinx.coroutines.CancellationException
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Instant

/** A token request whose DPoP proof and client authentication have been verified once. */
internal class AuthenticatedTokenRequest(
    val context: GrantContext,
    val clientAuthorization: VerifiedClientAuthorization?,
)

/**
 * The token endpoint's parse, RFC 9449 proof and client-authentication stages. Both the generic
 * grant dispatch and the token-exchange journey use this one implementation, so DPoP `jti`
 * replay state and client-assertion replay state are consumed exactly once per request.
 */
internal class TokenEndpointRequestAuthenticator(
    private val parseTokenRequestCommand: ParseTokenRequestCommand,
    private val verifyClientAuthenticationCommand: Lazy<VerifyClientAuthenticationCommand>,
    private val serversConfigProvider: OAuth2ServersConfigProvider,
    private val verifyDpopProofCommand: Lazy<VerifyDpopProofCommand>,
    private val dpopProofJtiCache: Lazy<DpopProofJtiCache>,
    private val dpopNonceManager: Lazy<DpopNonceManager>,
    private val log: SessionLogService,
) {
    suspend fun parse(
        applied: HandleTokenRequestArgs,
        timings: TokenPathStageTimings,
    ): IdkResult<TokenRequestData, IdkError> =
        timings.record(TokenPathStage.PARSE_REQUEST) {
            parseTokenRequestCommand.execute(
                ParseTokenRequestArgs(
                    requestBody = applied.requestBody,
                    requestHeaders = applied.requestHeaders,
                    httpUrl = applied.httpUrl,
                    clientCertificateDer = applied.clientCertificateDer,
                ),
            )
        }

    suspend fun authenticate(
        applied: HandleTokenRequestArgs,
        tokenRequest: TokenRequestData,
        tenantId: String,
        timings: TokenPathStageTimings,
    ): IdkResult<AuthenticatedTokenRequest, IdkError> {
        // RFC 9449 §5: verify any DPoP proof on the token request and bind the resulting JWK
        // thumbprint as `cnf.jkt` on the issued access token. The thumbprint from the verified
        // proof always wins over the optional `dpop_jkt` query parameter the wallet sent at
        // /authorize (which is just an upfront commitment per RFC 9449 §10).
        val proofJkt =
            timings
                .record(TokenPathStage.DPOP_PROOF_VERIFICATION) {
                    verifyDpopProofIfPresent(applied.httpUrl, tokenRequest.dpopProof, tokenRequest.httpMethod)
                }.getOrElse { error -> return IdkResult.err(error) }

        // Per OID4VCI 1.0 §6.1: when the AS advertises
        // `pre-authorized_grant_anonymous_access_supported=true`, the wallet MAY
        // include `client_id` in the pre-authorized-code token request as a bare
        // identifier. It is NOT subject to RFC 6749 client authentication and
        // need not be registered. The parser sees `client_id` without secret/cert
        // and classifies it as `ClientAuthenticationConfig.None(clientId)`, which
        // would otherwise trigger a registry lookup and reject unregistered
        // wallets with `invalid_client`. Downgrade to Anonymous here so the
        // verify command treats the request as unauthenticated, matching spec.
        val effectiveAuth =
            if (tokenRequest.grantType == GrantType.PRE_AUTHORIZED_CODE &&
                serversConfigProvider.serverConfig.grantTypesEnabled.contains(
                    GrantType.PRE_AUTHORIZED_CODE.value,
                ) &&
                tokenRequest.clientAuthentication is ClientAuthenticationConfig.None
            ) {
                ClientAuthenticationConfig.Anonymous
            } else {
                tokenRequest.clientAuthentication
            }

        // For none-auth code and refresh requests, the grant verifier has the persisted code or
        // refresh-token row needed to distinguish an admitted wallet from an unknown client.
        val deferNoneClientAuthenticationToGrantVerifier =
            effectiveAuth is ClientAuthenticationConfig.None &&
                tokenRequest.grantType in setOf(
                    GrantType.AUTHORIZATION_CODE,
                    GrantType.REFRESH_TOKEN,
                )
        val verifiedAuth =
            if (deferNoneClientAuthenticationToGrantVerifier) {
                VerifiedClientAuthentication(
                    clientId = tokenRequest.clientId,
                    method = ClientAuthenticationMethod.NONE,
                )
            } else {
                // Keep selected-command construction separate from execution. The command lives in
                // the request SessionScope and is only resolved here, so a request that defers or
                // skips client authentication never builds it, and its DI cost is not folded into
                // the registry and configuration I/O measured inside the command itself.
                val selectedVerifyClientAuthentication =
                    timings.record(TokenPathStage.CLIENT_AUTHENTICATION_COMMAND_RESOLUTION) {
                        verifyClientAuthenticationCommand.value
                    }
                timings
                    .record(TokenPathStage.CLIENT_AUTHENTICATION) {
                        selectedVerifyClientAuthentication.execute(
                            VerifyClientAuthenticationArgs(
                                clientAuthentication = effectiveAuth,
                                clientId = tokenRequest.clientId,
                                tokenEndpointUrl = applied.httpUrl,
                                endpoint = ClientAuthenticationEndpoint.TOKEN,
                            ),
                        )
                    }.getOrElse { error -> return IdkResult.err(error) }
            }

        val certThumbprint =
            computeCertThumbprintIfBound(
                clientCertificateDer = applied.clientCertificateDer,
                clientAuthorization = verifiedAuth.clientAuthorization,
            )

        return Ok(
            AuthenticatedTokenRequest(
                context =
                    GrantContext(
                        tokenRequest = tokenRequest,
                        tenantId = tenantId,
                        resolvedClientId = verifiedAuth.clientId,
                        clientInstanceKeyJkt = verifiedAuth.clientInstanceKey?.let(::generateJwkThumbprint),
                        proofJkt = proofJkt,
                        certThumbprintS256 = certThumbprint,
                        applied = applied,
                        serverConfig = serversConfigProvider.serverConfig,
                        walletInstanceAttestation = verifiedAuth.walletInstanceAttestation,
                        clientAuthorization = verifiedAuth.clientAuthorization,
                    ),
                clientAuthorization = verifiedAuth.clientAuthorization,
            ),
        )
    }

    /**
     * Verifies the DPoP proof when present, applies the RFC 9449 §8 nonce policy, and threads
     * jti-replay protection. Returns the JWK thumbprint when a proof verifies successfully, `null`
     * when no proof was presented and none is required.
     */
    private suspend fun verifyDpopProofIfPresent(
        httpUrl: String,
        dpopProofToken: String?,
        httpMethod: String,
    ): IdkResult<String?, IdkError> {
        val log = log.logManager.withTag("DPoPNonce")
        val nonceRequired = serversConfigProvider.serverConfig.dpopNonceRequired
        if (dpopProofToken == null) {
            // RFC 9449 §8: the `use_dpop_nonce` signal applies only to *presented* proofs that
            // are missing or carry a stale `nonce` claim. When no proof is presented at all the
            // grant handlers own the rejection. Each handler knows whether its own
            // sender-constrained material requires a proof and emits the spec-correct error:
            //   - Auth-code grant: `invalid_grant` when the code committed a `dpop_jkt`
            //     (RFC 9449 §10.1). Under FAPI2 / HAIP every auth code commits one because the
            //     front channel mandates DPoP, so this fully covers `EnsureHolderOfKeyRequired`.
            //   - Refresh-token grant: `invalid_grant` when the refresh token has `cnf.jkt`
            //     (RFC 9449 §5). `…-refresh-token`'s `CheckTokenEndpointReturnedInvalidClient
            //     GrantOrRequestError` rejects `invalid_dpop_proof` here, so the per-grant
            //     `invalid_grant` is the only spec-conforming response.
            // A blanket `invalid_dpop_proof` short-circuit at this layer fights both checks: it
            // pre-empts the grant handler before it can emit the right code, and the FAPI2 suite
            // condition above is more restrictive than RFC 9449 §11.1's `invalid_dpop_proof`.
            return Ok(null)
        }

        val verified =
            verifyDpopProofCommand.value
                .execute(
                    VerifyDpopProofOptions(
                        dpopProof = dpopProofToken,
                        httpMethod = httpMethod,
                        httpUrl = httpUrl,
                    ),
                ).getOrElse { error -> return invalidDpopProof(error.message.defaultMessage) }

        // RFC 9449 §8: when the AS requires a nonce, the proof's `nonce` claim MUST be
        // present and currently valid. Missing or stale nonces yield `use_dpop_nonce`
        // with a fresh nonce surfaced through the response's `DPoP-Nonce` header.
        if (nonceRequired) {
            val proofNonce = verified.payload.nonce
            if (proofNonce == null) {
                val fresh = dpopNonceManager.value.rotate()
                log.warn("Rejecting token request with use_dpop_nonce: DPoP proof carried no `nonce` claim. Issued fresh DPoP-Nonce='$fresh'.")
                return errOf(AuthorizationServerError.UseDpopNonce(dpopNonce = fresh))
            }
            if (!dpopNonceManager.value.isValid(proofNonce)) {
                val fresh = dpopNonceManager.value.rotate()
                log.warn(
                    "Rejecting token request with use_dpop_nonce: DPoP proof `nonce` claim '$proofNonce' is unknown or expired " +
                        "(not in the active rolling window). Issued fresh DPoP-Nonce='$fresh'.",
                )
                return errOf(AuthorizationServerError.UseDpopNonce(dpopNonce = fresh))
            }
        }

        val jti = verified.payload.jti
        val iat = Instant.fromEpochSeconds(verified.payload.iat)
        // Scope a proof identifier to its verified public key. UTF-8 byte-length framing
        // makes the address unambiguous even when either value contains delimiters.
        val thumbprint = verified.jwkThumbprint
        val replayAddress = "${thumbprint.encodeToByteArray().size}:$thumbprint${jti.encodeToByteArray().size}:$jti"
        val reserved =
            try {
                dpopProofJtiCache.value.recordIfNew(replayAddress, iat + DPOP_JTI_REPLAY_WINDOW)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                return invalidDpopProof("DPoP replay protection is unavailable")
            }
        if (!reserved) {
            return invalidDpopProof("DPoP proof could not be reserved against replay")
        }
        return Ok(verified.jwkThumbprint)
    }

    /**
     * RFC 8705 §3: bind the issued access token to the TLS client certificate when the
     * request arrived over mTLS AND either the client opted in
     * (`tlsClientCertificateBoundAccessTokens`) or the server-wide default is on. Per §3
     * this is independent of the client-auth method: a public client doing PKCE can still
     * get a cert-bound token if it presented a cert at the token endpoint.
     */
    private fun computeCertThumbprintIfBound(
        clientCertificateDer: ByteArray?,
        clientAuthorization: VerifiedClientAuthorization?,
    ): String? =
        clientCertificateDer?.let { certDer ->
            val serverConfig = serversConfigProvider.serverConfig
            val clientOptIn = clientAuthorization?.tlsClientCertificateBoundAccessTokens ?: false
            val serverOptIn = serverConfig.tlsClientCertificateBoundAccessTokens
            if (clientOptIn || serverOptIn) {
                hash(certDer, DigestAlg.SHA256).encodeToBase64Url()
            } else {
                null
            }
        }

    private companion object {
        // RFC 9449 §11.1 / ClientVerifyDpopProofCommandImpl: proof iat tolerance is 60s, so the
        // replay-protection window stays valid for a buffered 120s.
        private val DPOP_JTI_REPLAY_WINDOW = 120.seconds
    }
}
