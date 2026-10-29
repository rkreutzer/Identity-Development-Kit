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

package com.sphereon.oauth2.server.authorization.impl.command.discovery

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.service.TypedServiceCommandAdapter
import com.sphereon.crypto.core.kms.KmsProviderRegistry
import com.sphereon.di.session.SessionScope
import com.sphereon.oauth2.common.config.AuthorizationServerMode
import com.sphereon.oauth2.common.config.FeaturePolicy
import com.sphereon.oauth2.common.config.OAuth2ServerInstanceConfig
import com.sphereon.oauth2.common.config.OAuth2ServersConfigProvider
import com.sphereon.oauth2.common.config.OAuth2ServerInstanceIdProvider
import com.sphereon.oauth2.common.config.TokenFormat
import com.sphereon.oauth2.common.config.isEnabled
import com.sphereon.oauth2.common.config.isRequired
import com.sphereon.oauth2.common.model.AuthorizationServerMetadata
import com.sphereon.oauth2.server.authorization.command.BuildServerMetadataArgs
import com.sphereon.oauth2.server.authorization.command.BuildServerMetadataCommand
import com.sphereon.oauth2.server.authorization.command.token.GrantHandler
import com.sphereon.oauth2.server.authorization.error.AuthorizationServerError
import com.sphereon.oauth2.server.authorization.signing.AsServerSigningIdentifierResolver
import com.sphereon.oauth2.server.authorization.signing.AsSigningRequirement
import com.sphereon.oauth2.server.authorization.signing.CapturedAsServerConfig
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.Named
import dev.zacsweers.metro.SingleIn
import kotlinx.coroutines.CancellationException
import kotlin.experimental.ExperimentalObjCName
import kotlin.native.ObjCName

import dev.zacsweers.metro.ExposeImplBinding
/**
 * Implementation of [BuildServerMetadataCommand]: builds the authorization server metadata
 * document (RFC 8414 plus OIDC Discovery 1.0) from the current server configuration. Only valid
 * for [AuthorizationServerMode.HOSTED] servers, returns an error for `EXTERNAL` servers.
 *
 * **Composition pattern: `FeaturePolicy.whenEnabled { ... }`**
 *
 * Each feature area (PKCE, DPoP, JARM, mTLS, JAR, Attestation, Logout, etc.) contributes its
 * metadata fields inline, gated by the per-feature [FeaturePolicy] from [OAuth2ServerInstanceConfig].
 * `whenEnabled { fieldValue }` returns the field value when the policy is enabled and `null`
 * otherwise; the metadata builder folds nullable patches into the final document.
 *
 * This pattern is appropriate while:
 *  - the feature count stays at roughly fifteen items or fewer;
 *  - feature areas are mutually independent (one feature's metadata patch does not depend on
 *    another's enablement);
 *  - the entire document is small enough to scan in a single editor view.
 *
 * **Intended evolution path: `MetadataContributor`**
 *
 * Once feature count exceeds the threshold above, the inline `whenEnabled { }` blocks should be
 * extracted into a pluggable contributor SPI: a `MetadataContributor` interface contributed via
 * `@ContributesIntoSet(AppScope::class, binding = binding<MetadataContributor>())`, one
 * contributor per feature area (DPoP, JARM, mTLS, Attestation, Logout, PAR, JAR, ...). Each
 * contributor owns the patch logic for its feature, lives next to that feature's other
 * implementation, and is unit-testable in isolation. [BuildServerMetadataCommandImpl] then folds
 * over the injected `Set<MetadataContributor>` instead of branching inline.
 *
 * The contributor pattern is deliberately deferred today: introducing it for the current feature
 * count adds DI graph surface and indirection without measurable readability gain. New feature
 * authors should add their patch inline using `FeaturePolicy.whenEnabled { ... }` until the
 * fifteen-item threshold is crossed, at which point the extraction is mechanical.
 *
 * Cross-reference: see `docs/oidf/2026-04-architecture-review.md` Section E for the full
 * architectural rationale and the threshold reasoning.
 */
@Inject
@SingleIn(SessionScope::class)
@OptIn(ExperimentalObjCName::class)
@ObjCName("BuildServerMetadataCommandImpl", exact = true)
@ExposeImplBinding
class BuildServerMetadataCommandImpl(
    execution: SessionExecution,
    private val configProvider: OAuth2ServersConfigProvider,
    private val asInstanceIdProvider: OAuth2ServerInstanceIdProvider,
    private val signingIdentifierResolver: AsServerSigningIdentifierResolver,
    private val grantHandlers: Map<String, Lazy<GrantHandler>>,
    private val kmsProviderRegistry: KmsProviderRegistry,
    private val buildSignedMetadata: com.sphereon.oauth2.server.authorization.command.BuildSignedAuthorizationServerMetadataCommand,
) : TypedServiceCommandAdapter<BuildServerMetadataArgs, AuthorizationServerMetadata, IdkError>(
        commandId = BuildServerMetadataCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<BuildServerMetadataArgs>(),
        outputTypeToken = typeToken<AuthorizationServerMetadata>(),
    ),
    BuildServerMetadataCommand,
    CapturedServerMetadataAssembler {
    override val commandId: String get() = BuildServerMetadataCommand.COMMAND_ID

    override suspend fun supports(args: Any): Boolean = args is BuildServerMetadataArgs

    override suspend fun doExecute(
        args: BuildServerMetadataArgs,
        applyDuring: (BuildServerMetadataArgs) -> BuildServerMetadataArgs,
    ): IdkResult<AuthorizationServerMetadata, IdkError> {
        val applied = applyDuring(args)
        return executeInternal(applied.serverId, applied.baseUrlOverride, applied.includeSignedMetadata)
            .mapError { IdkError.fromDTO(it) }
    }

    private suspend fun executeInternal(
        serverId: String?,
        baseUrlOverride: String?,
        includeSignedMetadata: Boolean,
    ): IdkResult<AuthorizationServerMetadata, AuthorizationServerError> {
        val root = configProvider.getConfig()
        val exactKey = serverId ?: asInstanceIdProvider.currentAsInstanceId() ?: root.defaultServer
        val captured =
            try {
                CapturedAsServerConfig.select(root, exactKey)
            } catch (expected: IllegalArgumentException) {
                return Err(AuthorizationServerError.InvalidRequest(details = expected.message ?: "Invalid authorization server"))
            } catch (expected: IllegalStateException) {
                return Err(AuthorizationServerError.InvalidRequest(details = expected.message ?: "Authorization server not found"))
            }
        val assembly = assembleCaptured(captured, baseUrlOverride, includeSignedMetadata, strictCapabilities = false)
        if (assembly.isErr) return Err(assembly.error)
        return Ok(assembly.value.metadata)
    }

    override suspend fun assembleCaptured(
        captured: CapturedAsServerConfig,
        baseUrlOverride: String?,
        includeSignedMetadata: Boolean,
        strictCapabilities: Boolean,
    ): IdkResult<CapturedServerMetadataAssembly, AuthorizationServerError> {
        val config = captured.server
            ?: return Err(AuthorizationServerError.InvalidRequest(details = "No hosted authorization server is configured"))

        // fail fast on config that advertises capabilities we cannot back. Cheap
        // enough to re-run every discovery hit — OIDF suite's very first request catches drift.
        val consistency = validateServerMetadataConsistency(config)
        if (!consistency.isOk) return Err(consistency.error)

        val independentSigningRequired =
            config.tokenFormat == TokenFormat.JWT || config.oidc.isEnabled || config.jarm.isEnabled || config.logout.isEnabled
        val requirement =
            when {
                independentSigningRequired || (includeSignedMetadata && config.signedMetadata.isRequired) -> AsSigningRequirement.REQUIRED
                includeSignedMetadata && config.signedMetadata.isEnabled -> AsSigningRequirement.OPTIONAL
                else -> AsSigningRequirement.NOT_REQUIRED
            }
        val signing =
            try {
                signingIdentifierResolver.selectSigning(captured, requirement)
            } catch (cancelled: kotlinx.coroutines.CancellationException) {
                throw cancelled
            } catch (expected: Exception) {
                return Err(AuthorizationServerError.ServerError(details = "Signing selection failed: ${expected.message}", exception = expected))
            }
        val serverIdentifier = signing.identifier
        val activeSigningAlgs = signing.algorithms
        if (config.oidc.isEnabled || config.jarm.isEnabled) {
            val unavailableIdTokenAlgs =
                config.idTokenSigningAlgValuesSupported.orEmpty().filterNot { configured ->
                    activeSigningAlgs.any { it.equals(configured, ignoreCase = true) }
                }
            if (unavailableIdTokenAlgs.isNotEmpty()) {
                return Err(
                    AuthorizationServerError.ServerError(
                        details = "Configured ID-token signing algorithms have no ACTIVE private key: ${unavailableIdTokenAlgs.joinToString()}",
                    ),
                )
            }
            val unavailableJarmAlgs =
                config.authorizationSigningAlgValuesSupported.orEmpty().filterNot { configured ->
                    activeSigningAlgs.any { it.equals(configured, ignoreCase = true) }
                }
            if (unavailableJarmAlgs.isNotEmpty()) {
                return Err(
                    AuthorizationServerError.ServerError(
                        details = "Configured JARM signing algorithms have no ACTIVE private key: ${unavailableJarmAlgs.joinToString()}",
                    ),
                )
            }
        }

        val issuerUrl =
            (
                baseUrlOverride?.takeIf { it.isNotBlank() }
                    ?: config.issuer
                    ?: return Err(
                        AuthorizationServerError.InvalidRequest(
                            details =
                                "OAuth2 server '${captured.serverKey}' has no issuer configured and no request-time baseUrl override; " +
                                    "set oauth2.servers.<id>.issuer or ensure the request carries Host + X-Forwarded-Proto headers",
                        ),
                    )
            )
        val baseUrl = issuerUrl.trimEnd('/')

        // RFC 8705 §5: when an operator deploys a separate mTLS host, every advertised mTLS
        // endpoint URL swaps the issuer host for that override but keeps the path so the regular
        // issuer host stays free of TLS-client-cert requirements. When no override is set, the
        // aliases reuse the regular issuer host so a TLS-terminating proxy can route on path
        // alone.
        val mtlsBaseUrl = config.mtls.whenEnabled { buildMtlsBaseUrl(baseUrl, config.mtlsEndpointHostOverride) }

        // Resolve the effective auth-method list once. Two FeaturePolicies extend the configured
        // base set so operators don't have to keep two fields in sync:
        //  - mTLS adds `tls_client_auth` / `self_signed_tls_client_auth` (RFC 8705 §5).
        //  - Attestation-based client auth adds `attest_jwt_client_auth` (IANA name registered by
        //    draft-ietf-oauth-attestation-based-client-auth §13.4). Auto-extending here also
        //    satisfies the §10.1 / §13.3 MUST that `client_attestation_*_alg_values_supported`
        //    accompanies the advertised method, since the gate below keys off this same list.
        val effectiveAuthMethods =
            buildList {
                addAll(config.tokenEndpointAuthMethodsSupported)
                if (config.mtls.isEnabled) {
                    if ("tls_client_auth" !in config.tokenEndpointAuthMethodsSupported) add("tls_client_auth")
                    if ("self_signed_tls_client_auth" !in config.tokenEndpointAuthMethodsSupported) add("self_signed_tls_client_auth")
                }
                if (config.attestation.isEnabled &&
                    "attest_jwt_client_auth" !in config.tokenEndpointAuthMethodsSupported
                ) {
                    add("attest_jwt_client_auth")
                }
            }
        val attestJwtClientAuthAdvertised = "attest_jwt_client_auth" in effectiveAuthMethods

        // Only verification-capability fields without configured lists need KMS enumeration.
        // One complete capture feeds all of them; observation fails closed on any provider error.
        val needsDerivedVerifyAlgs =
            (config.dpop.isEnabled && config.dpopSigningAlgValuesSupported == null) ||
                (attestJwtClientAuthAdvertised &&
                    (config.clientAttestationSigningAlgValuesSupported == null || config.clientAttestationPopSigningAlgValuesSupported == null)) ||
                (config.jar.isEnabled && config.requestObjectSigningAlgValuesSupported == null)
        val derivedVerifyAlgs =
            if (needsDerivedVerifyAlgs) {
                try {
                    deriveJwsVerifyAlgsFromKms(strictCapabilities).also { derived ->
                        if (strictCapabilities && derived.isEmpty()) {
                            return Err(AuthorizationServerError.ServerError(details = "No JWS verification capability is available"))
                        }
                    }
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (expected: Exception) {
                    if (!strictCapabilities) throw expected
                    return Err(AuthorizationServerError.ServerError(details = "KMS verification capability collection failed", exception = expected))
                }
            } else {
                emptyList()
            }

        val metadata =
            AuthorizationServerMetadata(
                issuer = issuerUrl,
                tokenEndpoint = canonicalTokenEndpointForIssuer(issuerUrl),
                authorizationEndpoint = "$baseUrl/authorize",
                jwksUri = config.jwksUri ?: "$baseUrl/.well-known/jwks.json",
                grantTypesSupported =
                    buildList {
                        addAll(config.grantTypesEnabled)
                        // Handler map keys are pure contribution metadata and do not construct any
                        // SessionScope handler merely to build discovery. Each URN is advertised
                        // only when its feature gate is on, so an operator who keeps
                        // `tokenExchange = NOT_SUPPORTED` or `deviceFlow = NOT_SUPPORTED` gets a
                        // discovery doc free of those URNs even though the handlers are wired.
                        val contributedGrantTypes = grantHandlers.keys
                        // RFC 8693: advertise the token-exchange URN when the handler is contributed
                        // and the feature is enabled. Operators flip the feature policy without having
                        // to hand-edit `grantTypesEnabled`.
                        if (config.tokenExchange.isEnabled &&
                            TOKEN_EXCHANGE_GRANT_URN in contributedGrantTypes &&
                            TOKEN_EXCHANGE_GRANT_URN !in config.grantTypesEnabled
                        ) {
                            add(TOKEN_EXCHANGE_GRANT_URN)
                        }
                        // RFC 8628: advertise the device-code grant URN when the handler is contributed
                        // and the device-flow feature is enabled, mirroring the token-exchange pattern.
                        if (config.deviceFlow.isEnabled &&
                            DEVICE_CODE_GRANT_URN in contributedGrantTypes &&
                            DEVICE_CODE_GRANT_URN !in config.grantTypesEnabled
                        ) {
                            add(DEVICE_CODE_GRANT_URN)
                        }
                    },
                responseTypesSupported = config.responseTypesSupported.toList(),
                scopesSupported = config.scopesSupported,
                authorizationDetailsTypesSupported = config.authorizationDetailsTypesSupported,
                // RFC 8705 §5: extend the advertised list with the mTLS auth methods when the
                // mTLS feature is enabled, so clients discover that `tls_client_auth` and
                // `self_signed_tls_client_auth` are accepted at the (mTLS) token endpoint.
                tokenEndpointAuthMethodsSupported = effectiveAuthMethods,
                codeChallengeMethodsSupported = config.pkce.whenEnabled { config.pkceMethodsSupported.toList() },
                // RFC 9449 §5.1: advertise the JWS algs that DPoP proofs may use. The AS only
                // verifies DPoP, so the alg list is bounded by what every wired KMS provider can
                // verify rather than by the AS's own signing key. Operator config wins when set.
                dpopSigningAlgValuesSupported =
                    config.dpop.whenEnabled {
                        config.dpopSigningAlgValuesSupported?.toList() ?: derivedVerifyAlgs
                    },
                requirePushedAuthorizationRequests =
                    when {
                        config.par.isRequired -> true
                        config.par.isEnabled -> false
                        else -> null
                    },
                pushedAuthorizationRequestEndpoint = config.par.whenEnabled { "$baseUrl/par" },
                // RFC 8628 §4: advertise the device authorization endpoint when the device-flow
                // feature is enabled. Discovery hides the field entirely when the feature is off
                // so RFC 8414 §2 default semantics apply.
                deviceAuthorizationEndpoint = config.deviceFlow.whenEnabled { "$baseUrl/device_authorization" },
                introspectionEndpoint = config.introspection.whenEnabled { "$baseUrl/introspect" },
                introspectionEndpointAuthMethodsSupported = config.introspection.whenEnabled { config.introspectionEndpointAuthMethodsSupported.toList() },
                revocationEndpoint = config.revocation.whenEnabled { "$baseUrl/revoke" },
                revocationEndpointAuthMethodsSupported = config.revocation.whenEnabled { config.revocationEndpointAuthMethodsSupported.toList() },
                // Attestation-based client auth metadata
                // (draft-ietf-oauth-attestation-based-client-auth -07/-08 §10 / §13.1 / §13.3).
                // The two `*_alg_values_supported` lists MUST be present whenever the
                // `attest_jwt_client_auth` token endpoint auth method is advertised, irrespective
                // of the FeaturePolicy flag — because that's what wallets/RPs gate their
                // negotiation on. Operator config wins; default falls back to whatever JWS algs
                // the wired KMS providers can verify so deployments don't have to hand-list them.
                // The "challenge required" signal is the presence of `challenge_endpoint` itself
                // (and the runtime `use_attestation_challenge` error code), mirroring how DPoP
                // signals nonce requirement via runtime errors rather than a metadata flag —
                // there is no separate `*_nonce_required` boolean in the attestation drafts.
                challengeEndpoint = config.attestation.whenEnabled { "$baseUrl/attestation-challenge".takeIf { config.attestationChallengeRequired } },
                clientAttestationSigningAlgValuesSupported =
                    if (attestJwtClientAuthAdvertised) {
                        config.clientAttestationSigningAlgValuesSupported?.toList() ?: derivedVerifyAlgs
                    } else {
                        null
                    },
                clientAttestationPopSigningAlgValuesSupported =
                    if (attestJwtClientAuthAdvertised) {
                        config.clientAttestationPopSigningAlgValuesSupported?.toList() ?: derivedVerifyAlgs
                    } else {
                        null
                    },
                walletInstanceAttestationRequired = config.walletInstanceAttestation.whenEnabled { config.walletInstanceAttestation.isRequired },
                preferredClientStatusPeriod = config.walletInstanceAttestation.whenEnabled { config.preferredClientStatusPeriodSeconds },
                // OIDC metadata (OpenID Connect Discovery 1.0)
                userinfoEndpoint = config.oidc.whenEnabled { "$baseUrl/userinfo" },
                subjectTypesSupported = config.oidc.whenEnabled { config.subjectTypesSupported },
                idTokenSigningAlgValuesSupported =
                    config.oidc.whenEnabled { config.idTokenSigningAlgValuesSupported?.toList() ?: activeSigningAlgs.toList() },
                // OIDC Discovery §3 — full standard claim set across all five OIDC scopes
                // (openid + profile + email + address + phone). Operators can override via
                // config.claimsSupported when they expose a narrower or wider set.
                claimsSupported =
                    config.oidc.whenEnabled {
                        config.claimsSupported ?: listOf(
                            "sub",
                            "name",
                            "given_name",
                            "family_name",
                            "middle_name",
                            "nickname",
                            "preferred_username",
                            "profile",
                            "picture",
                            "website",
                            "gender",
                            "birthdate",
                            "zoneinfo",
                            "locale",
                            "updated_at",
                            "email",
                            "email_verified",
                            "address",
                            "phone_number",
                            "phone_number_verified",
                        )
                    },
                // OIDC Discovery §3 — the AS honors OIDC Core §5.5 `claims` request parameter
                // (claim names listed under `claims.userinfo` are returned from /userinfo even
                // when the granted scope alone wouldn't allow them; `claims.id_token` likewise).
                claimsParameterSupported = config.oidc.whenEnabled { true },
                // OID4VCI 1.1 Section 13.3 — Interactive Authorization Endpoint
                interactiveAuthorizationEndpoint = config.iae.whenEnabled { "$baseUrl/iae" },
                preAuthorizedGrantAnonymousAccessSupported = config.grantTypesEnabled.contains("urn:ietf:params:oauth:grant-type:pre-authorized_code"),
                // OIDC RP-Initiated Logout 1.0 §2 + Front-Channel Logout 1.0 §3 +
                // Back-Channel Logout 1.0 §2.1. Gated on `config.logout` so deployments that opt
                // out (e.g. headless backends without browser sessions) hide the entire logout
                // surface from discovery. The end-session endpoint is `/logout` on the AS's REST
                // surface; the AS advertises both Front-Channel and Back-Channel support and
                // includes `sid` in id_tokens (via `CreateIdTokenCommandImpl`) so RPs can correlate
                // the inbound `logout_token` back to the right local session.
                endSessionEndpoint = config.logout.whenEnabled { "$baseUrl/logout" },
                frontchannelLogoutSupported = config.logout.whenEnabled { true },
                frontchannelLogoutSessionSupported = config.logout.whenEnabled { true },
                backchannelLogoutSupported = config.logout.whenEnabled { true },
                backchannelLogoutSessionSupported = config.logout.whenEnabled { true },
                // OIDF JARM (https://openid.net/specs/oauth-v2-jarm.html). Advertise the
                // signing/encryption alg lists and extend `response_modes_supported` with the
                // `*.jwt` variants only when JARM is enabled.
                authorizationSigningAlgValuesSupported =
                    config.jarm.whenEnabled { config.authorizationSigningAlgValuesSupported?.toList() ?: activeSigningAlgs.toList() },
                authorizationEncryptionAlgValuesSupported = config.jarm.whenEnabled { config.authorizationEncryptionAlgValuesSupported?.toList() },
                authorizationEncryptionEncValuesSupported = config.jarm.whenEnabled { config.authorizationEncryptionEncValuesSupported?.toList() },
                responseModesSupported =
                    buildList {
                        add("query")
                        add("fragment")
                        add("form_post")
                        if (config.jarm.isEnabled) {
                            add("jwt")
                            add("query.jwt")
                            add("fragment.jwt")
                            add("form_post.jwt")
                        }
                    },
                // RFC 9101 (JAR) discovery. Advertise `request` / `request_uri` support and the
                // accepted JWS algorithm list when the JAR feature is enabled. RP signs the
                // request object; the AS verifies — so the alg list reflects what the wired KMS
                // providers can verify, not the AS's own signing key. Explicit config wins.
                requestParameterSupported = config.jar.whenEnabled { true },
                requestUriParameterSupported = config.jar.whenEnabled { true },
                requireRequestUriRegistration = config.jar.whenEnabled { true.takeIf { config.requireRequestUriRegistration } },
                requestObjectSigningAlgValuesSupported =
                    config.jar.whenEnabled {
                        config.requestObjectSigningAlgValuesSupported?.toList()
                            ?: derivedVerifyAlgs
                    },
                // RFC 8705 §3.3 + §5: advertise certificate-bound access-token support and the
                // per-endpoint mTLS aliases when the mTLS feature is enabled.
                tlsClientCertificateBoundAccessTokens = config.mtls.whenEnabled { config.tlsClientCertificateBoundAccessTokens },
                mtlsEndpointAliases =
                    if (mtlsBaseUrl != null) {
                        buildMap {
                            put("token_endpoint", "$mtlsBaseUrl/token")
                            if (config.revocation.isEnabled) {
                                put("revocation_endpoint", "$mtlsBaseUrl/revoke")
                            }
                            if (config.introspection.isEnabled) {
                                put("introspection_endpoint", "$mtlsBaseUrl/introspect")
                            }
                            if (config.par.isEnabled) {
                                put("pushed_authorization_request_endpoint", "$mtlsBaseUrl/par")
                            }
                            if (config.oidc.isEnabled) {
                                put("userinfo_endpoint", "$mtlsBaseUrl/userinfo")
                            }
                            // RFC 8705 §5 lists `device_authorization_endpoint` among the endpoints
                            // that can carry an mTLS alias when the AS hosts a separate mTLS host.
                            if (config.deviceFlow.isEnabled) {
                                put("device_authorization_endpoint", "$mtlsBaseUrl/device_authorization")
                            }
                        }
                    } else {
                        null
                    },
                // RFC 9207 §3 / FAPI2-SP §5.3.2.2-7: advertise that authorization responses include
                // the `iss` parameter. CreateAuthorizationResponseCommandImpl always emits it when an
                // issuer is configured, so this is unconditionally true at the metadata layer.
                authorizationResponseIssParameterSupported = true,
            )

        // RFC 8414 §2 — when the deployment opts into signed_metadata, sign the
        // unsigned document with the AS's active signing key and embed the JWS as the
        // `signed_metadata` member. The signing key is the same one the AS uses for
        // id_tokens (already published in JWKS), so RPs that already trust JWKS can
        // verify the signed metadata with no extra key configuration.
        val effective =
            if (includeSignedMetadata && config.signedMetadata.isEnabled && serverIdentifier != null) {
                val signed =
                    buildSignedMetadata.execute(
                        com.sphereon.oauth2.server.authorization.command.BuildSignedAuthorizationServerMetadataArgs(
                            metadata = metadata,
                            signingKey = serverIdentifier,
                        ),
                    )
                if (signed.isOk) {
                    metadata.copy(signedMetadata = signed.value.jwt)
                } else {
                    // REQUIRED policy + sign failure must surface as a server error so
                    // an operator notices; SUPPORTED policy + sign failure degrades
                    // gracefully to the unsigned-only response (RPs that don't pin can
                    // still succeed; pinned RPs will fail their own JWS check).
                    if (config.signedMetadata.isRequired) {
                        return Err(
                            AuthorizationServerError.ServerError(
                                details = "signed_metadata=REQUIRED but signing failed: ${signed.error.message.defaultMessage}",
                            ),
                        )
                    }
                    metadata
                }
            } else {
                if (includeSignedMetadata && config.signedMetadata.isRequired) {
                    return Err(AuthorizationServerError.ServerError(details = "signed_metadata=REQUIRED but no ACTIVE signing key is available"))
                }
                metadata
            }

        return Ok(CapturedServerMetadataAssembly(effective, signing))
    }

    /**
     * Aggregate the JWS algs that any wired KMS provider can verify, mapped to their RFC 7518
     * names. Used as the default for metadata fields that describe what the AS *accepts* on
     * incoming JWTs (DPoP proofs, request objects, client attestation JWTs) — these reflect
     * verification capability, not the AS's own signing-key alg. Explicit operator config still
     * wins; this is the fallback when no list is configured.
     *
     * Algorithms with no JWS mapping (e.g. COSE-only or experimental curves) are silently dropped
     * rather than crashing — discovery should still succeed even if a provider exposes an alg the
     * JOSE family doesn't name.
     */
    private suspend fun deriveJwsVerifyAlgsFromKms(strictCapabilities: Boolean): List<String> {
        val jwsAlgs = linkedSetOf<String>()
        for (id in kmsProviderRegistry.getProviderIds()) {
            val capabilities =
                try {
                    kmsProviderRegistry.getProviderById(id).getCapabilities()
                } catch (cancelled: kotlinx.coroutines.CancellationException) {
                    throw cancelled
                } catch (expected: Exception) {
                    if (strictCapabilities) throw expected
                    log.warn("KMS provider '$id' getCapabilities() failed; excluded from discovery alg list: ${expected.message}")
                    continue
                }
            for (alg in capabilities.signatureAlgorithms) {
                runCatching { keyAlgorithmToJwsAlg(alg) }.onSuccess { jwsAlgs.add(it) }
            }
        }
        return jwsAlgs.toList()
    }


    /**
     * Compute the base URL used for [AuthorizationServerMetadata.mtlsEndpointAliases] entries
     * (RFC 8705 §5). When [hostOverride] is supplied the issuer host (and optional port) is
     * swapped for that override while the scheme and path are preserved; when it is `null`,
     * aliases reuse the regular issuer URL so a TLS-terminating proxy can route on path alone.
     *
     * The override may include a port (`mtls.example.com:8443`); when it does not, the
     * scheme's default port is used by clients per RFC 3986 §3.2.2.
     */
    private fun buildMtlsBaseUrl(
        baseUrl: String,
        hostOverride: String?,
    ): String {
        if (hostOverride.isNullOrBlank()) {
            return baseUrl
        }
        val schemeEnd = baseUrl.indexOf("://")
        if (schemeEnd < 0) {
            return baseUrl
        }
        val scheme = baseUrl.substring(0, schemeEnd)
        val afterScheme = baseUrl.substring(schemeEnd + 3)
        val pathStart = afterScheme.indexOf('/')
        val path =
            if (pathStart < 0) {
                ""
            } else {
                afterScheme.substring(pathStart)
            }
        return "$scheme://$hostOverride$path".trimEnd('/')
    }

    private companion object {
        /**
         * OIDC-mandated baseline alg. Used only as a defensive fallback when the resolver can't
         * report the actual key alg, and never as a silent default that could hide a config bug.
         */

        /** RFC 8693 Token Exchange grant_type URN. */
        const val TOKEN_EXCHANGE_GRANT_URN = "urn:ietf:params:oauth:grant-type:token-exchange"

        /** RFC 8628 Device Authorization Grant grant_type URN. */
        const val DEVICE_CODE_GRANT_URN = "urn:ietf:params:oauth:grant-type:device_code"
    }
}

/**
 * Emit a metadata field only when the controlling [FeaturePolicy] is enabled. Discovery hides the
 * field entirely (`null`) when the feature is disabled, so RFC 8414 § 2 default semantics apply.
 */
private inline fun <T> FeaturePolicy.whenEnabled(value: () -> T?): T? = if (isEnabled) value() else null

/** The same endpoint expression used by discovery, without request-derived trust decisions. */
internal fun canonicalTokenEndpointForIssuer(issuerUrl: String): String = "${issuerUrl.trimEnd('/')}/token"
