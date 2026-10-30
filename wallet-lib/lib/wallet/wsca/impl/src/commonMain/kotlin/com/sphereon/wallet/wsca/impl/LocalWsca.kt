/*
 * Copyright 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

package com.sphereon.wallet.wsca.impl

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.decodeFromBase64Url
import com.sphereon.core.api.encodeToBase64Url
import com.sphereon.core.api.encodeToHex
import com.sphereon.core.api.error.ErrorCategory
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.random.SecureRandom
import com.sphereon.core.api.service.EidasAssuranceLevel
import com.sphereon.core.compat.Uuid
import com.sphereon.crypto.core.generic.DigestAlg
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.crypto.core.generic.hash
import com.sphereon.crypto.core.jose.Jwk
import com.sphereon.crypto.core.jose.generateJwkThumbprint
import com.sphereon.di.session.SessionScope
import com.sphereon.oauth2.common.command.DpopProofAssembly
import com.sphereon.oauth2.common.command.DpopProofAssemblyRequest
import com.sphereon.wallet.unit.SecureComponentUsage
import com.sphereon.wallet.unit.WalletAttestedKeyRef
import com.sphereon.wallet.unit.WalletKeystoreRef
import com.sphereon.wallet.unit.WalletKeystoreSecurityLevel
import com.sphereon.wallet.unit.WalletPrivateKeyProtectionEvidence
import com.sphereon.wallet.unit.WalletProviderAttestationSignerRef
import com.sphereon.wallet.unit.WalletSecureComponentType
import com.sphereon.wallet.unit.WalletUserAuthenticationEvidence
import com.sphereon.wallet.unit.attestation.KeyAttestationIssueRequest
import com.sphereon.wallet.unit.attestation.KeyAttestationIssueResult
import com.sphereon.wallet.unit.attestation.Oid4vciKeyAttestationClaims
import com.sphereon.wallet.unit.attestation.Ts03KeyAttestationClaims
import com.sphereon.wallet.unit.attestation.Ts03KeyStorageClaim
import com.sphereon.wallet.unit.attestation.Ts03StatusClaim
import com.sphereon.wallet.unit.attestation.Ts03UserAuthenticationClaim
import com.sphereon.wallet.unit.attestation.WalletAttestationArtifact
import com.sphereon.wallet.unit.attestation.WalletAttestationArtifactMetadata
import com.sphereon.wallet.unit.attestation.WalletAttestationSignerProfile
import com.sphereon.wallet.unit.attestation.WalletAttestationSigningRequest
import com.sphereon.wallet.unit.attestation.WalletUnitAttestationEvidence
import com.sphereon.wallet.unit.attestation.WalletUnitAttestationFormat
import com.sphereon.wallet.unit.attestation.WalletUnitAttestationKind
import com.sphereon.wallet.unit.attestation.WalletUnitAttestationMaterial
import com.sphereon.wallet.unit.attestation.WalletUnitAttestationProfile
import com.sphereon.wallet.unit.attestation.WalletProviderAttestationSignerResolver
import com.sphereon.wallet.unit.attestation.compactJwtArtifactHash
import com.sphereon.wallet.unit.attestation.parseSignerProfile
import com.sphereon.wallet.unit.attestation.parseWalletAttestationSigningAlgorithm
import com.sphereon.wallet.wsca.Wsca
import com.sphereon.wallet.wsca.WscaClientAttestationAuthRequest
import com.sphereon.wallet.wsca.WscaClientAttestationAuthResult
import com.sphereon.wallet.wsca.WscaDpopProofRequest
import com.sphereon.wallet.wsca.WscaDpopProofResult
import com.sphereon.wallet.wsca.WscaPreparedSigning
import com.sphereon.wallet.wsca.WscaPreparedSigningFactory
import com.sphereon.wallet.wsca.WscaSigningRequest
import com.sphereon.wallet.wsca.WscaUserAuthRequest
import com.sphereon.wallet.wsca.WscaUserAuthentication
import com.sphereon.wallet.wscd.Wscd
import com.sphereon.wallet.wscd.WscdKeyHandle
import com.sphereon.wallet.wscd.WscdKeySpec
import com.sphereon.wallet.wscd.WscdProfile
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put
import kotlin.time.Clock
import kotlin.time.Duration.Companion.hours
import kotlin.time.Instant

/**
 * The local WSCA policy implementation of [Wsca]: assembles PoP/DPoP/client-attestation/key-
 * attestation JWTs. Holder keys and PoPs are signed through the injected [Wscd]. Wallet Provider
 * attestations are signed through [WalletProviderAttestationSignerResolver], so a production
 * Wallet Provider certificate chain is always paired with the key that actually owns it. This
 * class never touches a key manager service or any KMS-provider type directly.
 *
 * This implementation is fully stateless: unlike the WSCD, it keeps NO map of provisioned keys.
 * [ensureKey] and [createCredentialKey] simply forward to the WSCD's own idempotent/fresh key
 * primitives, and [sign] reconstructs a [WscdKeyHandle] from the caller-supplied
 * [WalletAttestedKeyRef] DTO (whose fields were themselves populated from a handle by this same
 * class) rather than resolving one from a local cache. The WSCD remains the single source of
 * truth for key custody and idempotency.
 */
@SingleIn(SessionScope::class)
@ContributesBinding(SessionScope::class, binding = binding<Wsca>())
class LocalWsca
    @Inject
    constructor(
        private val wscd: Wscd,
        private val dpopProofAssembly: DpopProofAssembly,
        userAuthenticator: WalletUserAuthenticator,
        private val walletProviderAttestationSignerResolver: WalletProviderAttestationSignerResolver,
        private val secureRandom: SecureRandom,
    ) : Wsca {
        private val preparedSigningFactory = WscaPreparedSigningFactory.create()

        override val wscdProfile: WscdProfile get() = wscd.profile
        override val userAuthentication: WscaUserAuthentication = LocalWscaUserAuthentication(userAuthenticator)

        override suspend fun ensureKey(
            walletUnitId: String,
            usage: SecureComponentUsage,
            algorithm: SignatureAlgorithm,
            keyAlias: String?,
        ): IdkResult<WalletAttestedKeyRef, IdkError> {
            val handle =
                wscd
                    .generateKey(WscdKeySpec(walletUnitId = walletUnitId, usage = usage, algorithm = algorithm, alias = keyAlias))
                    .getOrElse { return Err(it) }
            return Ok(toWalletAttestedKeyRef(handle, algorithm, usage))
        }

        override suspend fun createCredentialKey(
            walletUnitId: String,
            usage: SecureComponentUsage,
            algorithm: SignatureAlgorithm,
        ): IdkResult<WalletAttestedKeyRef, IdkError> {
            val handle =
                wscd
                    .generateFreshKey(WscdKeySpec(walletUnitId = walletUnitId, usage = usage, algorithm = algorithm))
                    .getOrElse { return Err(it) }
            return Ok(toWalletAttestedKeyRef(handle, algorithm, usage))
        }

        override suspend fun discardCredentialKey(
            walletUnitId: String,
            keyRef: WalletAttestedKeyRef,
        ): IdkResult<Unit, IdkError> {
            if (keyRef.walletUnitId != null && keyRef.walletUnitId != walletUnitId) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Credential key belongs to a different wallet unit"))
            }
            return wscd.deleteKey(toWscdKeyHandle(keyRef, walletUnitId))
        }

        override suspend fun prepareSign(request: WscaSigningRequest): IdkResult<WscaPreparedSigning, IdkError> {
            return prepareSigning(request, OPERATION_TYPE_SIGN)
        }

        private suspend fun prepareSigning(
            request: WscaSigningRequest,
            operationType: String,
        ): IdkResult<WscaPreparedSigning, IdkError> {
            validateSigningRequest(request).getOrElse { return Err(it) }
            val digestBinding = "sha256:${hash(request.signingInput, DigestAlg.SHA256).encodeToHex()}"
            val nonce = request.nonce?.takeIf { it.isNotBlank() } ?: secureRandom.newToken(lengthBytes = NONCE_RANDOM_BYTES)
            return Ok(
                preparedSigningFactory.mint(
                    walletUnitId = request.walletUnitId,
                    keyRef = request.keyRef,
                    walletAccountId = request.walletAccountId,
                    operationBinding = request.operationBinding,
                    operationType = operationType,
                    digestBinding = digestBinding,
                    nonce = nonce,
                    audience = request.audience?.takeIf { it.isNotBlank() } ?: request.operationBinding,
                    signingInput = request.signingInput,
                ),
            )
        }

        override suspend fun sign(
            prepared: WscaPreparedSigning,
            request: WscaSigningRequest,
        ): IdkResult<ByteArray, IdkError> {
            return signPrepared(prepared, request, OPERATION_TYPE_SIGN)
        }

        private suspend fun signPrepared(
            prepared: WscaPreparedSigning,
            request: WscaSigningRequest,
            expectedOperationType: String,
        ): IdkResult<ByteArray, IdkError> {
            validatePreparedSigning(prepared, request, expectedOperationType).getOrElse { return Err(it) }
            val activation =
                userAuthentication
                    .authenticate(
                        WscaUserAuthRequest(
                            walletUnitId = prepared.walletUnitId,
                            operationType = expectedOperationType,
                            operationBinding = prepared.operationBinding,
                            operationKeyRef = prepared.keyRef.keyRef ?: prepared.keyRef.keyId,
                            walletAccountId = prepared.walletAccountId,
                            digestBinding = prepared.digestBinding,
                            nonce = prepared.nonce,
                            audience = prepared.audience,
                        ),
                    )
                    .getOrElse { return Err(it) }
            return wscd.signDigest(toWscdKeyHandle(prepared.keyRef, prepared.walletUnitId), prepared.signingInput, activation)
        }

        private fun validateSigningRequest(request: WscaSigningRequest): IdkResult<Unit, IdkError> {
            if (request.keyRef.walletUnitId != null && request.keyRef.walletUnitId != request.walletUnitId) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "WSCA key belongs to a different wallet unit"))
            }
            if (request.walletAccountId != null && request.keyRef.walletAccountId != null && request.walletAccountId != request.keyRef.walletAccountId) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "WSCA key belongs to a different wallet account"))
            }
            return Ok(Unit)
        }

        private fun validatePreparedSigning(
            prepared: WscaPreparedSigning,
            request: WscaSigningRequest,
            expectedOperationType: String,
        ): IdkResult<Unit, IdkError> {
            validateSigningRequest(request).getOrElse { return Err(it) }
            if (!preparedSigningFactory.owns(prepared) || prepared.operationType != expectedOperationType ||
                prepared.walletUnitId != request.walletUnitId || prepared.keyRef != request.keyRef ||
                prepared.walletAccountId != request.walletAccountId || prepared.operationBinding != request.operationBinding ||
                prepared.audience != (request.audience ?: request.operationBinding) ||
                request.nonce != null && request.nonce != prepared.nonce ||
                !prepared.signingInput.contentEquals(request.signingInput)
            ) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Signing request does not match its prepared WSCA context"))
            }
            val expectedDigest = "sha256:${hash(request.signingInput, DigestAlg.SHA256).encodeToHex()}"
            if (prepared.digestBinding != expectedDigest) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Prepared WSCA digest binding does not match signing input"))
            }
            return Ok(Unit)
        }

        override suspend fun createDpopProof(request: WscaDpopProofRequest): IdkResult<WscaDpopProofResult, IdkError> {
            if (request.walletUnitId.isBlank()) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "DPoP walletUnitId must not be blank"))
            }
            if (request.httpMethod.isBlank()) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "DPoP httpMethod must not be blank"))
            }
            if (request.httpUrl.isBlank()) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "DPoP httpUrl must not be blank"))
            }

            val publicJwk = publicJwk(request.keyRef).getOrElse { return Err(it) }
            val handle = toWscdKeyHandle(request.keyRef, request.walletUnitId)
            val assembled =
                dpopProofAssembly.assemble(
                    DpopProofAssemblyRequest(
                        httpMethod = request.httpMethod,
                        httpUrl = request.httpUrl,
                        nonce = request.nonce,
                        accessToken = request.accessToken,
                        issuedAt = request.issuedAtEpochSeconds,
                    ),
                    publicJwk,
                )
            val signingRequest =
                WscaSigningRequest(
                    walletUnitId = request.walletUnitId,
                    keyRef = request.keyRef,
                    signingInput = assembled.signingInput,
                    operationBinding = request.operationBinding,
                    audience = request.httpUrl,
                    nonce = request.nonce,
                )
            val prepared = prepareSigning(signingRequest, OPERATION_TYPE_DPOP).getOrElse { return Err(it) }
            val signature = signPrepared(prepared, signingRequest, OPERATION_TYPE_DPOP).getOrElse { return Err(it) }
            return Ok(
                WscaDpopProofResult(
                    proofJwt = dpopProofAssembly.finish(assembled, signature),
                    jwkThumbprint = assembled.jwkThumbprint,
                ),
            )
        }

        override suspend fun createClientAttestationAuth(request: WscaClientAttestationAuthRequest,): IdkResult<WscaClientAttestationAuthResult, IdkError> {
            if (request.walletUnitId.isBlank()) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Client attestation walletUnitId must not be blank"))
            }
            if (request.clientId.isBlank()) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Client attestation clientId must not be blank"))
            }
            if (request.audience.isBlank()) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Client attestation audience must not be blank"))
            }
            if (request.walletName.isBlank()) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Client attestation walletName must not be blank"))
            }
            if (request.walletVersion.isBlank()) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Client attestation walletVersion must not be blank"))
            }

            val clientInstanceJwk = publicJwk(request.clientInstanceKey).getOrElse { return Err(it) }
            val signerAlgorithm = signatureAlgorithm(request.signer?.signingAlgorithm)
            val now = Clock.System.now()
            val expiresAt = request.expiresAt ?: Instant.fromEpochSeconds(now.epochSeconds + DEFAULT_ATTESTATION_TTL_SECONDS)
            val x5c = request.signer?.certificateChain.orEmpty()
            val issuer = request.signer?.issuer?.takeIf { it.isNotBlank() } ?: request.walletUnitId
            val signingAlg = joseAlgorithm(signerAlgorithm)

            val attestationHeader =
                buildJsonObject {
                    put("typ", "oauth-client-attestation+jwt")
                    put("alg", signingAlg)
                    if (x5c.isNotEmpty()) {
                        put("x5c", JsonArray(x5c.map { JsonPrimitive(it) }))
                    } else {
                        put("kid", request.signer?.keyId ?: request.signer?.signerId ?: request.walletUnitId)
                    }
                }
            val attestationPayload =
                buildJsonObject {
                    put("iss", issuer)
                    put("sub", request.clientId)
                    put("iat", now.epochSeconds)
                    put("nbf", now.epochSeconds)
                    put("exp", expiresAt.epochSeconds)
                    put("jti", Uuid.v4String())
                    put("wallet_name", request.walletName)
                    put("wallet_version", request.walletVersion)
                    request.walletLink?.let { put("wallet_link", it) }
                    put(
                        "cnf",
                        buildJsonObject {
                            put("jwk", json.encodeToJsonElement(Jwk.serializer(), clientInstanceJwk))
                        },
                    )
                }
            val attestationJwt =
                signWalletProviderCompactJwt(
                    walletUnitId = request.walletUnitId,
                    signerRef = request.signer,
                    protectedHeader = attestationHeader,
                    payload = attestationPayload,
                    operationBinding = request.operationBinding,
                    audience = request.audience,
                ).getOrElse { return Err(it) }

            val popHeader =
                buildJsonObject {
                    put("typ", "oauth-client-attestation-pop+jwt")
                    put("alg", request.clientInstanceKey.algorithm)
                }
            val popPayload =
                buildJsonObject {
                    put("iss", request.clientId)
                    put("aud", request.audience)
                    put("iat", now.epochSeconds)
                    put("jti", Uuid.v4String())
                    request.challenge?.let { put("challenge", it) }
                }
            val popJwt =
                signCompactJwt(
                    request.walletUnitId,
                    request.clientInstanceKey,
                    popHeader,
                    popPayload,
                    request.operationBinding,
                    request.audience,
                )
                    .getOrElse { return Err(it) }

            return Ok(
                WscaClientAttestationAuthResult(
                    clientId = request.clientId,
                    audience = request.audience,
                    clientAttestationJwt = attestationJwt,
                    clientAttestationPopJwt = popJwt,
                    clientInstanceJwkThumbprint = generateJwkThumbprint(clientInstanceJwk),
                ),
            )
        }

        override suspend fun attestKeys(request: KeyAttestationIssueRequest): IdkResult<KeyAttestationIssueResult, IdkError> =
            attestKeysInternal(request)

        private suspend fun attestKeysInternal(request: KeyAttestationIssueRequest): IdkResult<KeyAttestationIssueResult, IdkError> {
            if (request.profile == WalletUnitAttestationProfile.OID4VCI_JWT && request.requestedFormat != WalletUnitAttestationFormat.KEY_ATTESTATION_JWT) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Final OID4VCI key attestation requires the key-attestation JWT format"))
            }
            if (request.attestedKeys.isEmpty()) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Key attestation requires at least one attested key"))
            }
            if (request.audience.isBlank()) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Key attestation audience must not be blank"))
            }
            if (request.nonce.isBlank()) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Key attestation nonce must not be blank"))
            }

            val signerAlgorithm = signatureAlgorithm(request.signer?.signingAlgorithm)
            val now = Clock.System.now()
            val expiresAt = request.expiresAt ?: Instant.fromEpochSeconds(now.epochSeconds + DEFAULT_ATTESTATION_TTL_SECONDS)
            val statusSubject = request.statusSubject
            // Metadata mirror only (WalletUnitAttestationEvidence.keystore below) - unrelated to the
            // honest, profile-derived TS03 key_storage/user_authentication CLAIM values resolved next.
            val firstKeystore = request.keystore ?: request.attestedKeys.firstOrNull()?.keystore
            val x5c = request.signer?.certificateChain.orEmpty()
            val issuer = request.signer?.issuer?.takeIf { it.isNotBlank() } ?: request.walletUnitId

            // Honest KA claims: absent caller values are derived from
            // wscd.profile's capability ceiling; present caller values are rejected if they claim
            // MORE than that ceiling honestly backs.
            // Custody evidence (WscdKeyEvidence.evidence, e.g. LocalNative's device_keystore /
            // hardware_backing_preference) is key-independent for every Wscd implementation today
            // (SoftwareWscd and LocalNativeWscd both return a constant map once a key is
            // provisioned), so it is fetched ONCE per request from
            // the first attested key rather than once per attested key. Caller-supplied
            // request.evidence entries win on key collision; this call is purely additive/honest
            // enrichment, never a downgrade of caller-asserted evidence.
            val keyEvidence =
                wscd.keyEvidence(toWscdKeyHandle(request.attestedKeys.first(), request.walletUnitId)).getOrElse { return Err(it) }
            val mergedEvidence = keyEvidence.evidence + request.evidence

            val claims = if (request.profile == WalletUnitAttestationProfile.OID4VCI_JWT) {
                val publicKeys = request.attestedKeys.map { key ->
                    val encoded = key.publicKeyJwk
                        ?: return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Attested key requires a public JWK"))
                    runCatching { json.parseToJsonElement(encoded).jsonObject }.getOrElse {
                        return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Attested key public JWK is invalid"))
                    }
                }
                val finalClaims = runCatching {
                    Oid4vciKeyAttestationClaims(issuer, now.epochSeconds, expiresAt.epochSeconds, request.nonce, publicKeys)
                }.getOrElse { return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "OID4VCI key attestation claims are invalid")) }
                json.encodeToJsonElement(finalClaims).jsonObject
            } else {
                val keyStorage = resolveKeyStorageClaim(wscd.profile, request.keystore, request.privateKeyProtection)
                    .getOrElse { return Err(it) }
                val userAuthenticationClaim = resolveUserAuthenticationClaim(wscd.profile, request.userAuthentication)
                    .getOrElse { return Err(it) }
                json.encodeToJsonElement(Ts03KeyAttestationClaims(
                    iss = issuer,
                    sub = request.walletUnitId,
                    aud = request.audience,
                    iat = now.epochSeconds,
                    exp = expiresAt.epochSeconds,
                    jti = Uuid.v4String(),
                    attestedKeys = request.attestedKeys,
                    certification = request.evidence.ifEmpty { mapOf("profile" to request.profile.name) },
                    keyStorage = keyStorage,
                    userAuthentication = userAuthenticationClaim,
                    keyStorageStatus =
                        Ts03StatusClaim(
                            status = statusSubject?.let { "${it.statusListUri}#${it.index}" } ?: "urn:wallet-unit:key-storage-status:${request.walletUnitId}#0",
                            exp = expiresAt.epochSeconds,
                        ),
                    cNonce = request.nonce,
                    singleUse = request.singleUse,
                    evidence = mergedEvidence,
                )).jsonObject
            }

            val protectedHeader =
                JsonObject(
                    buildMap {
                        put("typ", JsonPrimitive(KEY_ATTESTATION_TYP))
                        put("alg", JsonPrimitive(joseAlgorithm(signerAlgorithm)))
                        if (x5c.isNotEmpty()) {
                            put("x5c", JsonArray(x5c.map { JsonPrimitive(it) }))
                        } else {
                            put("kid", JsonPrimitive(request.signer?.keyId ?: request.signer?.signerId ?: request.walletUnitId))
                        }
                    },
                )
            val compact =
                signWalletProviderCompactJwt(
                    walletUnitId = request.walletUnitId,
                    signerRef = request.signer,
                    protectedHeader = protectedHeader,
                    payload = claims,
                    operationBinding = request.operationBinding,
                ).getOrElse { return Err(it) }
            validateSelfIssuedKeyAttestation(
                compact, request.nonce,
                nonceClaim = if (request.profile == WalletUnitAttestationProfile.OID4VCI_JWT) "nonce" else "c_nonce",
            ).getOrElse { return Err(it) }
            val artifactHash = compactJwtArtifactHash(compact)
            val artifact =
                WalletAttestationArtifact(
                    kind = WalletUnitAttestationKind.KA,
                    profile = request.profile,
                    material = WalletUnitAttestationMaterial(WalletUnitAttestationFormat.KEY_ATTESTATION_JWT, compact),
                    issuedAt = now,
                    expiresAt = expiresAt,
                    statusSubject = request.statusSubject,
                    evidence =
                        WalletUnitAttestationEvidence(
                            profile = request.profile,
                            ts03Conformant = request.profile == WalletUnitAttestationProfile.TS03_JWT,
                            signer = request.signer,
                            keystore = firstKeystore,
                            userAuthentication = request.userAuthentication,
                            privateKeyProtection = request.privateKeyProtection,
                        ),
                    metadata =
                        WalletAttestationArtifactMetadata(
                            artifactHash = artifactHash,
                            statusSubject = request.statusSubject,
                            singleUse = request.singleUse,
                            signingEvidence =
                                mapOf(
                                    "alg" to joseAlgorithm(signerAlgorithm),
                                    "signerId" to (request.signer?.signerId ?: request.walletUnitId),
                                    "x5cCount" to x5c.size.toString(),
                                ),
                            claimSummary =
                                mapOf(
                                    "aud" to request.audience,
                                    "nonce" to request.nonce,
                                    "attestedKeyCount" to request.attestedKeys.size.toString(),
                                ),
                        ),
                )

            return Ok(
                KeyAttestationIssueResult(
                    walletUnitId = request.walletUnitId,
                    walletAccountId = request.walletAccountId,
                    attestationRef = artifactHash,
                    artifact = artifact,
                    nonce = request.nonce,
                    audience = request.audience,
                ),
            )
        }

        /**
         * Resolves the honest TS03 `key_storage` claim for [attestKeys].
         *
         * When the caller omits [requestedKeystore]/[requestedProtection], both `security_level` /
         * `secure_component` and `non_exportable` are derived from [profile]'s capability ceiling
         * ([WscdProfile.keyStorageSecurityLevel] / [WscdProfile.secureComponent] /
         * [WscdProfile.nonExportable]).
         *
         * When the caller supplies them, each is accepted only up to that ceiling:
         * - `security_level`: [WalletKeystoreSecurityLevel] declares its entries from strongest to
         *   weakest (`ISO_18045_HIGH` first), so a LOWER [WalletKeystoreSecurityLevel.ordinal] is a
         *   STRONGER claim. A caller-supplied level with a lower ordinal than the profile's ceiling
         *   claims more than the WSCD can honestly back and is rejected; an equal-or-higher ordinal
         *   (equal-or-weaker claim) is accepted verbatim.
         * - `secure_component`: [WalletSecureComponentType] is a categorical classification with no
         *   strength ordering, so it is enforced as an exact-match allow-list - only the profile's own
         *   [WscdProfile.secureComponent] value is accepted.
         * - `non_exportable`: claiming `true` when [profile] can only honestly back `false` is
         *   rejected; claiming `false` (a weaker claim) against any profile ceiling is accepted.
         */
        private fun resolveKeyStorageClaim(
            profile: WscdProfile,
            requestedKeystore: WalletKeystoreRef?,
            requestedProtection: WalletPrivateKeyProtectionEvidence?,
        ): IdkResult<Ts03KeyStorageClaim, IdkError> {
            val securityLevel = requestedKeystore?.securityLevel ?: profile.keyStorageSecurityLevel
            val secureComponent = requestedKeystore?.componentType ?: profile.secureComponent
            if (requestedKeystore != null) {
                if (securityLevel.ordinal < profile.keyStorageSecurityLevel.ordinal) {
                    return Err(
                        ceilingExceededError(
                            "Key attestation key_storage.security_level '${securityLevel.name}' exceeds this WSCD profile's " +
                                "honest ceiling '${profile.keyStorageSecurityLevel.name}'",
                        ),
                    )
                }
                if (secureComponent != profile.secureComponent) {
                    return Err(
                        ceilingExceededError(
                            "Key attestation key_storage.secure_component '${secureComponent.name}' does not match this WSCD " +
                                "profile's actual custody classification '${profile.secureComponent.name}'",
                        ),
                    )
                }
            }
            val nonExportable = requestedProtection?.nonExportable ?: profile.nonExportable
            if (requestedProtection != null && nonExportable && !profile.nonExportable) {
                return Err(
                    ceilingExceededError(
                        "Key attestation key_storage.non_exportable 'true' exceeds this WSCD profile's honest ceiling 'false'",
                    ),
                )
            }
            return Ok(
                Ts03KeyStorageClaim(
                    securityLevel = securityLevel.name.lowercase(),
                    secureComponent = secureComponent.name.lowercase(),
                    nonExportable = nonExportable,
                ),
            )
        }

        /**
         * Resolves the honest TS03 `user_authentication` claim for [attestKeys]. Absent
         * [requestedUserAuthentication], `assurance_level` is derived from
         * [profile]'s [WscdProfile.userAuthAssuranceLevel] ceiling. Present, it is parsed against the
         * [EidasAssuranceLevel] vocabulary (ordinal ascends from weakest `LOW` to strongest `HIGH`):
         * an unrecognized value cannot be verified against the ceiling and is rejected; a recognized
         * value with a HIGHER ordinal than the ceiling claims more assurance than the WSCD can
         * honestly back and is rejected; an equal-or-lower ordinal is accepted verbatim.
         */
        private fun resolveUserAuthenticationClaim(
            profile: WscdProfile,
            requestedUserAuthentication: WalletUserAuthenticationEvidence?,
        ): IdkResult<Ts03UserAuthenticationClaim, IdkError> {
            if (requestedUserAuthentication == null) {
                return Ok(
                    Ts03UserAuthenticationClaim(
                        assuranceLevel = profile.userAuthAssuranceLevel.serializedValue,
                        methods = emptyList(),
                    ),
                )
            }
            val requestedLevel =
                EidasAssuranceLevel.entries.firstOrNull {
                    it.serializedValue.equals(requestedUserAuthentication.assuranceLevel, ignoreCase = true)
                } ?: return Err(
                    ceilingExceededError(
                        "Key attestation user_authentication.assurance_level '${requestedUserAuthentication.assuranceLevel}' is not a " +
                            "recognized eIDAS assurance level and cannot be verified against this WSCD profile's honest ceiling " +
                            "'${profile.userAuthAssuranceLevel.serializedValue}'",
                    ),
                )
            if (requestedLevel.ordinal > profile.userAuthAssuranceLevel.ordinal) {
                return Err(
                    ceilingExceededError(
                        "Key attestation user_authentication.assurance_level '${requestedLevel.serializedValue}' exceeds this WSCD " +
                            "profile's honest ceiling '${profile.userAuthAssuranceLevel.serializedValue}'",
                    ),
                )
            }
            return Ok(
                Ts03UserAuthenticationClaim(
                    assuranceLevel = requestedLevel.serializedValue,
                    methods = requestedUserAuthentication.methods,
                ),
            )
        }

        private fun ceilingExceededError(message: String): IdkError =
            IdkError.fromString(
                code = "WALLET_WSCD_KEY_ATTESTATION_CEILING_EXCEEDED",
                category = ErrorCategory.VALIDATION,
                message = message,
            )

        private suspend fun signCompactJwt(
            walletUnitId: String,
            signerKey: WalletAttestedKeyRef,
            protectedHeader: JsonObject,
            payload: JsonObject,
            operationBinding: String,
            audience: String? = null,
        ): IdkResult<String, IdkError> {
            val encodedHeader = json.encodeToString(protectedHeader).encodeToByteArray().encodeToBase64Url()
            val encodedPayload = json.encodeToString(payload).encodeToByteArray().encodeToBase64Url()
            val signingInput = "$encodedHeader.$encodedPayload".encodeToByteArray()
            val request =
                WscaSigningRequest(
                    walletUnitId = walletUnitId,
                    keyRef = signerKey,
                    signingInput = signingInput,
                    operationBinding = operationBinding,
                    audience = audience,
                )
            val prepared = prepareSign(request).getOrElse { return Err(it) }
            val signature = sign(prepared, request).getOrElse { return Err(it) }
            return Ok("$encodedHeader.$encodedPayload.${signature.encodeToBase64Url()}")
        }

        private suspend fun signWalletProviderCompactJwt(
            walletUnitId: String,
            signerRef: WalletProviderAttestationSignerRef?,
            protectedHeader: JsonObject,
            payload: JsonObject,
            operationBinding: String,
            audience: String? = null,
        ): IdkResult<String, IdkError> {
            if (signerRef == null) {
                val localKey =
                    ensureKey(
                        walletUnitId = walletUnitId,
                        usage = SecureComponentUsage.WALLET_ATTESTATION,
                        algorithm = SignatureAlgorithm.ECDSA_SHA256,
                        keyAlias = null,
                    ).getOrElse { return Err(it) }
                return signCompactJwt(walletUnitId, localKey, protectedHeader, payload, operationBinding, audience)
            }

            val algorithm = parseWalletAttestationSigningAlgorithm(signerRef).getOrElse { return Err(it) }
            val signerProfile = parseSignerProfile(signerRef).getOrElse { return Err(it) }
            if (signerProfile == WalletAttestationSignerProfile.LOCAL_WSCD) {
                val localSignatureAlgorithm = signatureAlgorithm(signerRef.signingAlgorithm)
                val keyAlias =
                    signerRef.keyId?.takeIf { it.isNotBlank() }
                        ?: return Err(
                            IdkError.ILLEGAL_ARGUMENT_ERROR(
                                message = "LOCAL_WSCD Wallet Provider attestation signer '${signerRef.signerId}' requires a keyId",
                            ),
                        )
                val localKey =
                    ensureKey(
                        walletUnitId = walletUnitId,
                        usage = SecureComponentUsage.WALLET_ATTESTATION,
                        algorithm = localSignatureAlgorithm,
                        keyAlias = keyAlias,
                    ).getOrElse { return Err(it) }
                val keyOwner =
                    localKey.walletUnitId?.takeIf { it.isNotBlank() }
                        ?: return Err(
                            IdkError.fromString(
                                code = "WALLET_WSCA_PROVIDER_KEY_OWNER_MISSING",
                                category = ErrorCategory.VALIDATION,
                                message = "LOCAL_WSCD provider signer key has no wallet-unit owner",
                            ),
                        )
                if (keyOwner != walletUnitId) {
                    return Err(
                        IdkError.fromString(
                            code = "WALLET_WSCA_PROVIDER_KEY_CROSS_UNIT_NOT_AUTHORIZED",
                            category = ErrorCategory.VALIDATION,
                            message = "Holder key-attestation signing cannot use a provider key owned by '$keyOwner'",
                        ),
                    )
                }
                // Provider attestations use the exact key resolved and ownership-checked by the
                // provider boundary. Keep the requested holder wallet unit in KA claims/result,
                // while WSCA signing validation follows the actual key owner.
                return signCompactJwt(keyOwner, localKey, protectedHeader, payload, operationBinding, audience)
            }
            val signer = walletProviderAttestationSignerResolver.resolve(signerRef).getOrElse { return Err(it) }
            val encodedHeader = json.encodeToString(protectedHeader).encodeToByteArray().encodeToBase64Url()
            val encodedPayload = json.encodeToString(payload).encodeToByteArray().encodeToBase64Url()
            val signingInput = "$encodedHeader.$encodedPayload".encodeToByteArray()
            val signed =
                signer
                    .sign(
                        WalletAttestationSigningRequest(
                            algorithm = algorithm,
                            signerProfile = signerProfile,
                            signerId = signerRef.signerId,
                            signingInput = signingInput,
                            x5c = signerRef.certificateChain,
                            providerId = signerRef.providerId,
                            keyId = signerRef.keyId,
                        ),
                    ).getOrElse { return Err(it) }
            return Ok("$encodedHeader.$encodedPayload.${signed.signature.encodeToBase64Url()}")
        }

        private fun publicJwk(keyRef: WalletAttestedKeyRef): IdkResult<Jwk, IdkError> =
            try {
                val publicKeyJwk =
                    keyRef.publicKeyJwk
                        ?: return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Secure-component key '${keyRef.keyId}' does not contain a public JWK"))
                Ok(json.decodeFromString(Jwk.serializer(), publicKeyJwk))
            } catch (expected: Exception) {
                Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message = "Secure-component key '${keyRef.keyId}' does not contain a valid public JWK: ${expected.message}",
                        throwable = expected,
                    ),
                )
            }

        /**
         * Wraps a freshly-generated [WscdKeyHandle] into the holder-facing [WalletAttestedKeyRef] DTO.
         * `securityLevel`/`componentType` are pinned to the local-software values here (this class has
         * no other custody profile wired in this phase); a future profile-aware WSCA can derive them
         * from [WscdProfile] instead.
         */
        private fun toWalletAttestedKeyRef(
            handle: WscdKeyHandle,
            algorithm: SignatureAlgorithm,
            usage: SecureComponentUsage,
        ): WalletAttestedKeyRef =
            WalletAttestedKeyRef(
                keyId = handle.keyId ?: handle.keyRef,
                algorithm = joseAlgorithm(algorithm),
                publicKeyJwk = handle.publicKeyJwk,
                keyRef = handle.keyRef,
                walletUnitId = handle.walletUnitId,
                keystore =
                    WalletKeystoreRef(
                        id = handle.keyRef,
                        namespace = KEY_NAMESPACE,
                        providerId = handle.providerId,
                        securityLevel = WalletKeystoreSecurityLevel.NONE,
                        componentType = WalletSecureComponentType.LOCAL_WSCD,
                        usages = setOf(usage),
                    ),
            )

        /**
         * Reconstructs a [WscdKeyHandle] purely from a caller-supplied [WalletAttestedKeyRef] DTO -
         * the inverse of [toWalletAttestedKeyRef]. This is what lets [sign] and [createDpopProof] stay
         * stateless: every field the WSCD needs to resolve and use the key was already carried in the
         * DTO when it was handed back to the caller.
         */
        private fun toWscdKeyHandle(
            keyRef: WalletAttestedKeyRef,
            walletUnitId: String,
        ): WscdKeyHandle =
            WscdKeyHandle(
                keyRef = keyRef.keyRef ?: keyRef.keyId,
                profile = wscd.profile,
                walletUnitId = keyRef.walletUnitId ?: walletUnitId,
                publicKeyJwk = keyRef.publicKeyJwk,
                keyId = keyRef.keyId,
                providerId = keyRef.keystore?.providerId,
            )

        /**
         * Self-validation of a just-signed key-attestation JWT: decodes
         * [compactJwt]'s payload and re-checks the invariants a verifier would enforce against the
         * ACTUAL signed bytes returned to the caller, not just the pre-signing [Ts03KeyAttestationClaims]
         * object - catching any assembly/encoding defect between building that object and producing the
         * compact JWS. [maxTtlSeconds] mirrors `LocalWalletProvider.issueInstanceAttestation`'s WIA
         * TTL ceiling (24 hours): no KA-specific ceiling is declared anywhere in the TS03 models, so the
         * same honest technical ceiling applies.
         */
        internal fun validateSelfIssuedKeyAttestation(
            compactJwt: String,
            expectedNonce: String,
            maxTtlSeconds: Long = ATTESTATION_MAX_TTL_SECONDS,
            nonceClaim: String = "c_nonce",
        ): IdkResult<Unit, IdkError> {
            val parts = compactJwt.split('.')
            if (parts.size != 3) {
                return Err(selfValidationError("Key attestation JWT is not a compact JWS (expected 3 dot-separated parts, got ${parts.size})"))
            }
            val payload =
                try {
                    Json.parseToJsonElement(parts[1].decodeFromBase64Url().decodeToString()).jsonObject
                } catch (expected: Exception) {
                    return Err(selfValidationError("Key attestation JWT payload could not be decoded: ${expected.message}"))
                }
            val iat =
                payload["iat"]?.jsonPrimitive?.longOrNull
                    ?: return Err(selfValidationError("Key attestation JWT payload is missing a numeric 'iat'"))
            val exp =
                payload["exp"]?.jsonPrimitive?.longOrNull
                    ?: return Err(selfValidationError("Key attestation JWT payload is missing a numeric 'exp'"))
            if (exp <= iat) {
                return Err(selfValidationError("Key attestation JWT 'exp' ($exp) must be strictly after 'iat' ($iat)"))
            }
            if (exp - iat > maxTtlSeconds) {
                return Err(
                    selfValidationError(
                        "Key attestation JWT lifetime (${exp - iat}s) exceeds the honest ceiling of ${maxTtlSeconds}s",
                    ),
                )
            }
            val cNonce = payload[nonceClaim]?.jsonPrimitive?.contentOrNull
            if (cNonce != expectedNonce) {
                return Err(selfValidationError("Key attestation JWT '$nonceClaim' does not match the request nonce"))
            }
            return Ok(Unit)
        }

        private fun selfValidationError(message: String): IdkError =
            IdkError.fromString(
                code = "WALLET_WSCD_KEY_ATTESTATION_SELF_VALIDATION_FAILED",
                category = ErrorCategory.INTERNAL,
                message = message,
            )

        private fun joseAlgorithm(algorithm: SignatureAlgorithm): String =
            when (algorithm) {
                SignatureAlgorithm.ECDSA_SHA256 -> "ES256"
                SignatureAlgorithm.ECDSA_SHA384 -> "ES384"
                SignatureAlgorithm.ECDSA_SHA512 -> "ES512"
                SignatureAlgorithm.ED25519, SignatureAlgorithm.ED448 -> "EdDSA"
                else -> algorithm.toString()
            }

        private fun signatureAlgorithm(joseAlgorithm: String?): SignatureAlgorithm =
            when (joseAlgorithm?.uppercase()) {
                null, "", "ES256" -> SignatureAlgorithm.ECDSA_SHA256
                "ES384" -> SignatureAlgorithm.ECDSA_SHA384
                "ES512" -> SignatureAlgorithm.ECDSA_SHA512
                "EDDSA" -> SignatureAlgorithm.ED25519
                else -> SignatureAlgorithm.ECDSA_SHA256
            }

        private companion object {
            // Matches SoftwareWscd's own KEY_NAMESPACE: a coincidence of value, not a shared contract
            // - this one labels WalletKeystoreRef.namespace on the DTO surfaced to callers, the
            // WSCD's is an internal alias-derivation detail LocalWsca never sees.
            const val KEY_NAMESPACE: String = "wallet-units"
            const val KEY_ATTESTATION_TYP: String = "key-attestation+jwt"
            const val DEFAULT_ATTESTATION_TTL_SECONDS: Long = 300
            const val NONCE_RANDOM_BYTES: Int = 16

            /** Mirrors `LocalWalletProvider.issueInstanceAttestation`'s WIA TTL ceiling (24 hours). */
            val ATTESTATION_MAX_TTL_SECONDS: Long = 24.hours.inWholeSeconds
            const val OPERATION_TYPE_SIGN: String = "wallet.wsca.local.sign"
            const val OPERATION_TYPE_DPOP: String = "wallet.wsca.local.dpop-proof"
            val json =
                Json {
                    encodeDefaults = false
                    explicitNulls = false
                }
        }
    }
