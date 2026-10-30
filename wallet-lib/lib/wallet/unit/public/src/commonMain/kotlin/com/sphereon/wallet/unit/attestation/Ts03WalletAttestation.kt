/*
 * Copyright 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

package com.sphereon.wallet.unit.attestation

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.decodeFromBase64Url
import com.sphereon.core.api.encodeToBase64Url
import com.sphereon.core.api.error.IdkError
import com.sphereon.crypto.core.generic.DigestAlg
import com.sphereon.crypto.core.generic.hash
import com.sphereon.wallet.unit.EudiWalletTrustDecision
import com.sphereon.wallet.unit.EudiWalletTrustEvidence
import com.sphereon.wallet.unit.EudiWalletTrustService
import com.sphereon.wallet.unit.ResolveWalletProviderTrustRequest
import com.sphereon.wallet.unit.ResolveWalletSolutionTrustRequest
import com.sphereon.wallet.unit.WalletAttestationStatusEvidence
import com.sphereon.wallet.unit.WalletAttestedKeyRef
import com.sphereon.wallet.unit.WalletSolutionRef
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlin.time.Clock

@Serializable
enum class WalletAttestationSigningAlgorithm(
    val jwtAlg: String,
    val digest: DigestAlg
) {
    ES256("ES256", DigestAlg.SHA256),
    ES384("ES384", DigestAlg.SHA384),
    ES512("ES512", DigestAlg.SHA512),
}

@Serializable
enum class WalletAttestationSignerProfile {
    LOCAL_EVALUATION,
    LOCAL_WSCD,
    REMOTE_WSCD,
    EXTERNAL_PROVIDER,
}

@Serializable
enum class Ts03WalletAttestationValidationProfile {
    LOCAL_EVALUATION,
    WALLET_PROVIDER_TRUST_LIST,
}

@Serializable
data class Ts03WalletAttestationValidationPolicy(
    val profile: Ts03WalletAttestationValidationProfile = Ts03WalletAttestationValidationProfile.LOCAL_EVALUATION,
    val allowedAlgorithms: Set<String> = setOf("ES256", "ES384", "ES512"),
    val requireX5c: Boolean = false,
    val requireJoseSignatureVerification: Boolean = false,
    val requireWalletProviderTrust: Boolean = false,
    val requireWalletSolutionTrust: Boolean = false,
    val requireStatusEvidence: Boolean = false,
    val acceptedSignerCertificateProfiles: Set<String> = emptySet(),
    val requiredWalletProviderRole: String? = null,
    val requiredWalletProviderServiceType: String? = null,
    val requiredWalletSolutionRole: String? = null,
    val requiredWalletSolutionServiceType: String? = null,
) {
    companion object {
        fun localEvaluation(): Ts03WalletAttestationValidationPolicy = Ts03WalletAttestationValidationPolicy()

        fun walletProviderTrustList(): Ts03WalletAttestationValidationPolicy =
            Ts03WalletAttestationValidationPolicy(
                profile = Ts03WalletAttestationValidationProfile.WALLET_PROVIDER_TRUST_LIST,
                requireX5c = true,
                requireJoseSignatureVerification = true,
                requireWalletProviderTrust = true,
                requireWalletSolutionTrust = true,
                requireStatusEvidence = true,
                acceptedSignerCertificateProfiles = setOf("ETSI_TS_119_412_6_WALLET_PROVIDER"),
            )
    }
}

@Serializable
data class WalletAttestationSigningRequest(
    val algorithm: WalletAttestationSigningAlgorithm,
    val signerProfile: WalletAttestationSignerProfile,
    val signerId: String,
    val signingInput: ByteArray,
    val x5c: List<String> = emptyList(),
    val providerId: String? = null,
    val keyId: String? = null,
) {
    override fun equals(other: Any?): Boolean =
        other is WalletAttestationSigningRequest &&
            algorithm == other.algorithm &&
            signerProfile == other.signerProfile &&
            signerId == other.signerId &&
            signingInput.contentEquals(other.signingInput) &&
            x5c == other.x5c &&
            providerId == other.providerId &&
            keyId == other.keyId

    override fun hashCode(): Int {
        var result = algorithm.hashCode()
        result = 31 * result + signerProfile.hashCode()
        result = 31 * result + signerId.hashCode()
        result = 31 * result + signingInput.contentHashCode()
        result = 31 * result + x5c.hashCode()
        result = 31 * result + (providerId?.hashCode() ?: 0)
        result = 31 * result + (keyId?.hashCode() ?: 0)
        return result
    }
}

@Serializable
data class WalletAttestationSigningResult(
    val signature: ByteArray,
    val algorithm: WalletAttestationSigningAlgorithm,
    val signerProfile: WalletAttestationSignerProfile,
    val signerId: String,
    val x5c: List<String> = emptyList(),
    val keyId: String? = null,
    val evidence: Map<String, String> = emptyMap(),
) {
    override fun equals(other: Any?): Boolean =
        other is WalletAttestationSigningResult &&
            signature.contentEquals(other.signature) &&
            algorithm == other.algorithm &&
            signerProfile == other.signerProfile &&
            signerId == other.signerId &&
            x5c == other.x5c &&
            keyId == other.keyId &&
            evidence == other.evidence

    override fun hashCode(): Int {
        var result = signature.contentHashCode()
        result = 31 * result + algorithm.hashCode()
        result = 31 * result + signerProfile.hashCode()
        result = 31 * result + signerId.hashCode()
        result = 31 * result + x5c.hashCode()
        result = 31 * result + (keyId?.hashCode() ?: 0)
        result = 31 * result + evidence.hashCode()
        return result
    }
}

interface WalletAttestationSigner {
    suspend fun sign(request: WalletAttestationSigningRequest): com.sphereon.core.api.IdkResult<WalletAttestationSigningResult, com.sphereon.core.api.error.IdkError>
}

class LocalEvaluationWalletAttestationSigner(
    private val signerId: String = "local-evaluation-wallet-attestation-signer",
    private val secret: String = "local-evaluation-only",
) : WalletAttestationSigner {
    override suspend fun sign(request: WalletAttestationSigningRequest,): com.sphereon.core.api.IdkResult<WalletAttestationSigningResult, com.sphereon.core.api.error.IdkError> {
        if (request.signerProfile != WalletAttestationSignerProfile.LOCAL_EVALUATION) {
            return com.sphereon.core.api.Err(
                com.sphereon.core.api.error.IdkError
                    .ILLEGAL_ARGUMENT_ERROR(message = "Local evaluation signer only accepts LOCAL_EVALUATION profile"),
            )
        }
        val signature = hash(request.signingInput + secret.encodeToByteArray(), request.algorithm.digest)
        return com.sphereon.core.api.Ok(
            WalletAttestationSigningResult(
                signature = signature,
                algorithm = request.algorithm,
                signerProfile = WalletAttestationSignerProfile.LOCAL_EVALUATION,
                signerId = signerId,
                keyId = request.keyId,
                evidence = mapOf("signerProfile" to "local-evaluation", "production" to "false"),
            ),
        )
    }
}

@Serializable
data class Ts03StatusClaim(
    val status: String,
    val exp: Long,
)

@Serializable
data class Ts03WalletInstanceAttestationClaims(
    val iss: String,
    val sub: String,
    val aud: String,
    val iat: Long,
    val exp: Long,
    val jti: String,
    @SerialName("wallet_name")
    val walletName: String,
    @SerialName("wallet_version")
    val walletVersion: String,
    @SerialName("wallet_link")
    val walletLink: String? = null,
    @SerialName("wallet_solution_certification_information")
    val walletSolutionCertificationInformation: Map<String, String>,
    @SerialName("client_status")
    val clientStatus: Ts03StatusClaim,
    val cnf: Map<String, String> = emptyMap(),
    val evidence: Map<String, String> = emptyMap(),
)

@Serializable
data class Ts03KeyStorageClaim(
    @SerialName("security_level")
    val securityLevel: String,
    @SerialName("secure_component")
    val secureComponent: String,
    @SerialName("non_exportable")
    val nonExportable: Boolean,
)

@Serializable
data class Ts03UserAuthenticationClaim(
    @SerialName("assurance_level")
    val assuranceLevel: String,
    val methods: List<String> = emptyList(),
)

@Serializable
data class Ts03KeyAttestationClaims(
    val iss: String,
    val sub: String,
    val aud: String,
    val iat: Long,
    val exp: Long,
    val jti: String,
    @SerialName("attested_keys")
    val attestedKeys: List<WalletAttestedKeyRef>,
    val certification: Map<String, String>,
    @SerialName("key_storage")
    val keyStorage: Ts03KeyStorageClaim,
    @SerialName("user_authentication")
    val userAuthentication: Ts03UserAuthenticationClaim,
    @SerialName("key_storage_status")
    val keyStorageStatus: Ts03StatusClaim,
    @SerialName("c_nonce")
    val cNonce: String? = null,
    @SerialName("single_use")
    val singleUse: Boolean = true,
    val evidence: Map<String, String> = emptyMap(),
)

@Serializable
data class Ts03JwtHeader(
    val alg: String,
    val typ: String = "JWT",
    val kid: String? = null,
    val x5c: List<String> = emptyList(),
)

@Serializable
data class Ts03EncodedJwt(
    val compact: String,
    val artifactHash: String,
    val signingEvidence: Map<String, String>,
)

fun compactJwtArtifactHash(compactJwt: String): String = "sha256:${hash(compactJwt.encodeToByteArray(), DigestAlg.SHA256).encodeToBase64Url()}"

class Ts03WalletAttestationEncoder(
    private val json: Json =
        Json {
            encodeDefaults = false
            explicitNulls = false
        },
) {
    suspend fun encodeWalletInstanceAttestation(
        claims: Ts03WalletInstanceAttestationClaims,
        signer: WalletAttestationSigner,
        signingRequest: WalletAttestationSigningRequest,
    ): com.sphereon.core.api.IdkResult<Ts03EncodedJwt, com.sphereon.core.api.error.IdkError> =
        encodeCompactJwt(json.encodeToString(claims), signer, signingRequest, typ = WALLET_INSTANCE_ATTESTATION_TYP)

    suspend fun encodeKeyAttestation(
        claims: Ts03KeyAttestationClaims,
        signer: WalletAttestationSigner,
        signingRequest: WalletAttestationSigningRequest,
    ): com.sphereon.core.api.IdkResult<Ts03EncodedJwt, com.sphereon.core.api.error.IdkError> =
        encodeCompactJwt(json.encodeToString(claims), signer, signingRequest, typ = KEY_ATTESTATION_TYP)

    suspend fun encodeOid4vciKeyAttestation(
        claims: Oid4vciKeyAttestationClaims,
        signer: WalletAttestationSigner,
        signingRequest: WalletAttestationSigningRequest,
    ): IdkResult<Ts03EncodedJwt, IdkError> =
        encodeCompactJwt(json.encodeToString(claims), signer, signingRequest, typ = KEY_ATTESTATION_TYP)

    private suspend fun encodeCompactJwt(
        claimsJson: String,
        signer: WalletAttestationSigner,
        signingRequest: WalletAttestationSigningRequest,
        typ: String,
    ): com.sphereon.core.api.IdkResult<Ts03EncodedJwt, com.sphereon.core.api.error.IdkError> {
        // encodeDefaults=false would drop Ts03JwtHeader.typ's default "JWT", so pass typ
        // explicitly (KA requires key-attestation+jwt per OpenID4VCI KeyAttestationVerifier).
        val headerJson =
            json.encodeToString(
                Ts03JwtHeader(
                    alg = signingRequest.algorithm.jwtAlg,
                    typ = typ,
                    kid = signingRequest.keyId,
                    x5c = signingRequest.x5c,
                ),
            )
        val header = headerJson.encodeToByteArray().encodeToBase64Url()
        val payload = claimsJson.encodeToByteArray().encodeToBase64Url()
        val signingInput = "$header.$payload".encodeToByteArray()
        val signed =
            signer.sign(signingRequest.copy(signingInput = signingInput)).getOrElse {
                return com.sphereon.core.api
                    .Err(it)
            }
        val signature = signed.signature.encodeToBase64Url()
        val compact = "$header.$payload.$signature"
        return com.sphereon.core.api.Ok(
            Ts03EncodedJwt(
                compact = compact,
                artifactHash = compactJwtArtifactHash(compact),
                signingEvidence =
                    signed.evidence +
                        mapOf(
                            "alg" to signed.algorithm.jwtAlg,
                            "signerId" to signed.signerId,
                            "signerProfile" to signed.signerProfile.name,
                            "issuedAt" to Clock.System.now().toString(),
                        ),
            ),
        )
    }

    private companion object {
        const val KEY_ATTESTATION_TYP: String = "key-attestation+jwt"
        /** WIA is not yet constrained to a protocol typ elsewhere; keep JWT until a TS03 WIA typ is wired. */
        const val WALLET_INSTANCE_ATTESTATION_TYP: String = "JWT"
    }
}

@Serializable
data class Ts03JoseVerificationRequest(
    val compactJwt: String,
    val trustedJwks: JsonObject? = null,
)

@Serializable
data class Ts03JoseVerificationEvidence(
    val valid: Boolean,
    val signerKeyId: String? = null,
    val signerFingerprint: String? = null,
    val evidence: Map<String, String> = emptyMap(),
    val failureReason: String? = null,
)

interface Ts03JoseVerifier {
    suspend fun verify(request: Ts03JoseVerificationRequest): IdkResult<Ts03JoseVerificationEvidence, IdkError>
}

data class Ts03DecodedJwt<Claims>(
    val header: Ts03JwtHeader,
    val claims: Claims,
    val headerJson: String,
    val payloadJson: String,
)

class Ts03WalletAttestationValidator(
    private val joseVerifier: Ts03JoseVerifier? = null,
    private val trustService: EudiWalletTrustService? = null,
    private val json: Json =
        Json {
            ignoreUnknownKeys = true
            encodeDefaults = false
            explicitNulls = false
        },
) : WalletUnitAttestationMaterialValidator {
    override suspend fun validateWalletInstanceAttestation(request: WalletInstanceAttestationValidationRequest,): IdkResult<Ts1194723ValidationResult, IdkError> {
        if (request.material.format != WalletUnitAttestationFormat.JWT) {
            return Ok(
                validationResult(
                    valid = false,
                    format = request.material.format,
                    errors = listOf("WIA material must be a TS03 JWT"),
                ),
            )
        }
        val decoded =
            decodeCompactJwt<Ts03WalletInstanceAttestationClaims>(request.material)
                .getOrElse {
                    return Ok(
                        validationResult(
                            valid = false,
                            format = request.material.format,
                            errors = listOf(it.message.defaultMessage),
                        ),
                    )
                }
        val errors = mutableListOf<String>()
        val evidence = mutableMapOf<String, String>()
        val now = request.validationTimeEpochSeconds ?: Clock.System.now().epochSeconds
        val policy = request.validationPolicy

        validateCommonJwt(
            compactJwt = request.material.value,
            header = decoded.header,
            issuer = decoded.claims.iss,
            audience = decoded.claims.aud,
            issuedAt = decoded.claims.iat,
            expiresAt = decoded.claims.exp,
            expectedIssuer = request.expectedIssuer,
            expectedAudience = request.expectedAudience,
            trust = request.trust,
            policy = policy,
            nowEpochSeconds = now,
            clockSkewSeconds = request.clockSkewSeconds,
            errors = errors,
            evidence = evidence,
        )
        requireNotBlank(decoded.claims.sub, "WIA wallet instance identity", errors)
        requireNotBlank(decoded.claims.walletName, "WIA wallet_name", errors)
        requireNotBlank(decoded.claims.walletVersion, "WIA wallet_version", errors)
        if (decoded.claims.walletSolutionCertificationInformation.isEmpty()) {
            errors += "WIA wallet_solution_certification_information is missing"
        }
        validateStatusClaim(
            label = "client_status",
            status = decoded.claims.clientStatus,
            statusEvidence = request.trust.statusEvidence,
            requireStatusEvidence = policy.requireStatusEvidence,
            nowEpochSeconds = now,
            errors = errors,
            evidence = evidence,
        )
        val providerTrust = resolveWalletProviderTrust(decoded.claims.iss, decoded.header.x5c, request.trust, policy, now)
        validateTrustEvidence("Wallet Provider", providerTrust, policy.requireWalletProviderTrust, policy.acceptedSignerCertificateProfiles, now, errors, evidence)
        val walletSolutionTrust = resolveWalletSolutionTrust(decoded.claims.walletName, decoded.claims.walletVersion, request.trust, policy, now)
        validateTrustEvidence("Wallet Solution", walletSolutionTrust, policy.requireWalletSolutionTrust, emptySet(), now, errors, evidence)

        evidence +=
            mapOf(
                "kind" to "WIA",
                "alg" to decoded.header.alg,
                "issuer" to decoded.claims.iss,
                "audience" to decoded.claims.aud,
                "walletSolution" to "${decoded.claims.walletName}:${decoded.claims.walletVersion}",
            )
        return Ok(validationResult(valid = errors.isEmpty(), format = request.material.format, evidence = evidence, errors = errors))
    }

    override suspend fun validateKeyAttestation(request: KeyAttestationValidationRequest,): IdkResult<Ts1194723ValidationResult, IdkError> {
        if (request.material.format !in setOf(WalletUnitAttestationFormat.KEY_ATTESTATION_JWT, WalletUnitAttestationFormat.JWT)) {
            return Ok(
                validationResult(
                    valid = false,
                    format = request.material.format,
                    errors = listOf("KA material must be a TS03 key-attestation JWT"),
                ),
            )
        }
        val decoded =
            decodeCompactJwt<Ts03KeyAttestationClaims>(request.material)
                .getOrElse {
                    return Ok(
                        validationResult(
                            valid = false,
                            format = request.material.format,
                            errors = listOf(it.message.defaultMessage),
                        ),
                    )
                }
        val errors = mutableListOf<String>()
        val evidence = mutableMapOf<String, String>()
        val now = request.validationTimeEpochSeconds ?: Clock.System.now().epochSeconds
        val policy = request.validationPolicy

        validateCommonJwt(
            compactJwt = request.material.value,
            header = decoded.header,
            issuer = decoded.claims.iss,
            audience = decoded.claims.aud,
            issuedAt = decoded.claims.iat,
            expiresAt = decoded.claims.exp,
            expectedIssuer = request.expectedIssuer,
            expectedAudience = request.expectedAudience,
            trust = request.trust,
            policy = policy,
            nowEpochSeconds = now,
            clockSkewSeconds = request.clockSkewSeconds,
            errors = errors,
            evidence = evidence,
        )
        requireNotBlank(decoded.claims.sub, "KA subject", errors)
        if (decoded.claims.cNonce != request.expectedNonce) {
            errors += "KA c_nonce does not match expected nonce"
        }
        if (decoded.claims.attestedKeys.isEmpty()) {
            errors += "KA attested_keys is missing"
        }
        if (decoded.claims.attestedKeys.any { it.algorithm !in policy.allowedAlgorithms }) {
            errors += "KA attested_keys contains an unsupported algorithm"
        }
        if (decoded.claims.certification.isEmpty()) {
            errors += "KA certification is missing"
        }
        requireNotBlank(decoded.claims.keyStorage.securityLevel, "KA key_storage.security_level", errors)
        requireNotBlank(decoded.claims.keyStorage.secureComponent, "KA key_storage.secure_component", errors)
        requireNotBlank(decoded.claims.userAuthentication.assuranceLevel, "KA user_authentication.assurance_level", errors)
        if (request.requiredKeyStorage.isNotEmpty() && decoded.claims.keyStorage.securityLevel !in request.requiredKeyStorage) {
            errors += "KA key_storage.security_level does not satisfy required policy"
        }
        if (request.requiredUserAuthentication.isNotEmpty() && decoded.claims.userAuthentication.assuranceLevel !in request.requiredUserAuthentication) {
            errors += "KA user_authentication.assurance_level does not satisfy required policy"
        }
        validateStatusClaim(
            label = "key_storage_status",
            status = decoded.claims.keyStorageStatus,
            statusEvidence = request.trust.statusEvidence,
            requireStatusEvidence = policy.requireStatusEvidence,
            nowEpochSeconds = now,
            errors = errors,
            evidence = evidence,
        )
        val providerTrust = resolveWalletProviderTrust(decoded.claims.iss, decoded.header.x5c, request.trust, policy, now)
        validateTrustEvidence("Wallet Provider", providerTrust, policy.requireWalletProviderTrust, policy.acceptedSignerCertificateProfiles, now, errors, evidence)

        evidence +=
            mapOf(
                "kind" to "KA",
                "alg" to decoded.header.alg,
                "issuer" to decoded.claims.iss,
                "audience" to decoded.claims.aud,
                "keyStorageSecurityLevel" to decoded.claims.keyStorage.securityLevel,
            )
        return Ok(validationResult(valid = errors.isEmpty(), format = request.material.format, evidence = evidence, errors = errors))
    }

    private suspend fun validateCommonJwt(
        compactJwt: String,
        header: Ts03JwtHeader,
        issuer: String,
        audience: String,
        issuedAt: Long,
        expiresAt: Long,
        expectedIssuer: String?,
        expectedAudience: String,
        trust: WalletUnitAttestationTrustInput,
        policy: Ts03WalletAttestationValidationPolicy,
        nowEpochSeconds: Long,
        clockSkewSeconds: Long,
        errors: MutableList<String>,
        evidence: MutableMap<String, String>,
    ) {
        if (policy.profile != Ts03WalletAttestationValidationProfile.WALLET_PROVIDER_TRUST_LIST && policy.profile != Ts03WalletAttestationValidationProfile.LOCAL_EVALUATION) {
            errors += "Unsupported TS03 validation profile '${policy.profile}'"
        }
        if (header.alg !in policy.allowedAlgorithms) {
            errors += "Unsupported TS03 signing algorithm '${header.alg}'"
        }
        if (policy.requireX5c && header.x5c.isEmpty()) {
            errors += "TS03 JWT is missing required x5c signer certificate chain"
        }
        if (expectedIssuer != null && issuer != expectedIssuer) {
            errors += "JWT issuer does not match expected issuer"
        }
        if (audience != expectedAudience) {
            errors += "JWT audience does not match expected audience"
        }
        if (issuedAt > nowEpochSeconds + clockSkewSeconds) {
            errors += "JWT issued-at is in the future"
        }
        if (expiresAt + clockSkewSeconds < nowEpochSeconds) {
            errors += "JWT technical expiry has passed"
        }
        if (policy.requireJoseSignatureVerification) {
            val verifier = joseVerifier
            if (verifier == null) {
                errors += "JOSE signature verification evidence is missing"
            } else {
                val verified = verifier.verify(Ts03JoseVerificationRequest(compactJwt, trust.trustedJwks))
                if (verified.isErr) {
                    errors += "JOSE signature verification failed: ${verified.error.message.defaultMessage}"
                } else if (!verified.value.valid) {
                    errors += "JOSE signature verification failed${verified.value.failureReason?.let { ": $it" } ?: ""}"
                } else {
                    evidence += verified.value.evidence
                    verified.value.signerKeyId?.let { evidence["joseSignerKeyId"] = it }
                    verified.value.signerFingerprint?.let { evidence["joseSignerFingerprint"] = it }
                }
            }
        }
        evidence["x5cCount"] = header.x5c.size.toString()
    }

    private suspend fun resolveWalletProviderTrust(
        providerId: String,
        signerCertificateChain: List<String>,
        trust: WalletUnitAttestationTrustInput,
        policy: Ts03WalletAttestationValidationPolicy,
        nowEpochSeconds: Long,
    ): EudiWalletTrustEvidence? {
        trust.walletProviderTrustEvidence?.let { return it }
        if (!policy.requireWalletProviderTrust) return null
        val service = trustService ?: return null
        return try {
            service.resolveWalletProviderTrust(
                ResolveWalletProviderTrustRequest(
                    providerId = providerId,
                    signerCertificateChain = signerCertificateChain,
                    requiredLoteRole = policy.requiredWalletProviderRole,
                    requiredServiceType = policy.requiredWalletProviderServiceType,
                    requiredCertificateProfile = policy.acceptedSignerCertificateProfiles.firstOrNull(),
                    validationTimeEpochSeconds = nowEpochSeconds,
                ),
            )
        } catch (e: Throwable) {
            EudiWalletTrustEvidence(trusted = false, decision = EudiWalletTrustDecision.UNTRUSTED, failureReason = e.message ?: "Wallet Provider trust resolution failed")
        }
    }

    private suspend fun resolveWalletSolutionTrust(
        walletName: String,
        walletVersion: String,
        trust: WalletUnitAttestationTrustInput,
        policy: Ts03WalletAttestationValidationPolicy,
        nowEpochSeconds: Long,
    ): EudiWalletTrustEvidence? {
        trust.walletSolutionTrustEvidence?.let { return it }
        if (!policy.requireWalletSolutionTrust) return null
        val service = trustService ?: return null
        return try {
            service.resolveWalletSolutionTrust(
                ResolveWalletSolutionTrustRequest(
                    walletSolution = WalletSolutionRef(name = walletName, version = walletVersion),
                    requiredLoteRole = policy.requiredWalletSolutionRole,
                    requiredServiceType = policy.requiredWalletSolutionServiceType,
                    validationTimeEpochSeconds = nowEpochSeconds,
                ),
            )
        } catch (e: Throwable) {
            EudiWalletTrustEvidence(trusted = false, decision = EudiWalletTrustDecision.UNTRUSTED, failureReason = e.message ?: "Wallet Solution trust resolution failed")
        }
    }

    private fun validateTrustEvidence(
        label: String,
        trustEvidence: EudiWalletTrustEvidence?,
        required: Boolean,
        acceptedSignerCertificateProfiles: Set<String>,
        nowEpochSeconds: Long,
        errors: MutableList<String>,
        evidence: MutableMap<String, String>,
    ) {
        if (trustEvidence == null) {
            if (required) errors += "$label trust evidence is missing"
            return
        }
        if (!trustEvidence.trusted || trustEvidence.decision in invalidTrustDecisions) {
            errors += "$label trust evidence is not trusted${trustEvidence.failureReason?.let { ": $it" } ?: ""}"
        }
        if (trustEvidence.expiresAtEpochSeconds != null && trustEvidence.expiresAtEpochSeconds < nowEpochSeconds) {
            errors += "$label trust evidence is expired"
        }
        if (trustEvidence.revokedAtEpochSeconds != null || trustEvidence.serviceStatus.equals("revoked", ignoreCase = true)) {
            errors += "$label trust evidence is revoked"
        }
        if (acceptedSignerCertificateProfiles.isNotEmpty()) {
            val profile = trustEvidence.signingCertificateProfile
            if (profile == null || profile !in acceptedSignerCertificateProfiles) {
                errors += "$label signer certificate profile is unsupported"
            }
        }
        trustEvidence.trustListUri?.let { evidence["${label.evidencePrefix()}TrustListUri"] = it }
        trustEvidence.trustAnchor?.let { evidence["${label.evidencePrefix()}TrustAnchor"] = it }
        trustEvidence.matchedCertificateFingerprint?.let { evidence["${label.evidencePrefix()}MatchedCertificateFingerprint"] = it }
    }

    private fun validateStatusClaim(
        label: String,
        status: Ts03StatusClaim,
        statusEvidence: WalletAttestationStatusEvidence?,
        requireStatusEvidence: Boolean,
        nowEpochSeconds: Long,
        errors: MutableList<String>,
        evidence: MutableMap<String, String>,
    ) {
        val parsed = parseStatus(status.status)
        if (parsed == null) {
            errors += "$label must contain a status list URI and index"
        } else {
            evidence["${label}Uri"] = parsed.first
            evidence["${label}Index"] = parsed.second
        }
        if (status.exp < nowEpochSeconds) {
            errors += "$label maintenance expiry has passed"
        }
        if (statusEvidence == null) {
            if (requireStatusEvidence) errors += "$label status evidence is missing"
            return
        }
        if (parsed != null && (statusEvidence.statusListUri != parsed.first || statusEvidence.index != parsed.second)) {
            errors += "$label status evidence does not match the JWT status reference"
        }
        if (statusEvidence.revoked) {
            errors += "$label status evidence is revoked"
        }
        if (statusEvidence.maintenanceExpiresAtEpochSeconds != null && statusEvidence.maintenanceExpiresAtEpochSeconds < nowEpochSeconds) {
            errors += "$label status evidence maintenance expiry has passed"
        }
        if (statusEvidence.failureReason != null) {
            errors += "$label status evidence failed: ${statusEvidence.failureReason}"
        }
    }

    private inline fun <reified Claims> decodeCompactJwt(material: WalletUnitAttestationMaterial,): IdkResult<Ts03DecodedJwt<Claims>, IdkError> {
        val parts = material.value.split('.')
        if (parts.size != 3) {
            return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "TS03 JWT must use compact JWS serialization"))
        }
        return try {
            val headerJson = parts[0].decodeFromBase64Url().decodeToString()
            val payloadJson = parts[1].decodeFromBase64Url().decodeToString()
            Ok(
                Ts03DecodedJwt(
                    header = json.decodeFromString<Ts03JwtHeader>(headerJson),
                    claims = json.decodeFromString<Claims>(payloadJson),
                    headerJson = headerJson,
                    payloadJson = payloadJson,
                ),
            )
        } catch (e: Throwable) {
            Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "TS03 JWT could not be decoded: ${e.message ?: "invalid compact JWT"}"))
        }
    }

    private fun validationResult(
        valid: Boolean,
        format: WalletUnitAttestationFormat,
        evidence: Map<String, String> = emptyMap(),
        errors: List<String> = emptyList(),
    ): Ts1194723ValidationResult =
        Ts1194723ValidationResult(
            valid = valid,
            format = format,
            evidence = evidence,
            errors = errors,
        )

    private fun parseStatus(status: String): Pair<String, String>? {
        val marker = status.lastIndexOf('#')
        if (marker <= 0 || marker == status.lastIndex) return null
        return status.substring(0, marker) to status.substring(marker + 1)
    }

    private fun requireNotBlank(
        value: String,
        label: String,
        errors: MutableList<String>
    ) {
        if (value.isBlank()) errors += "$label is missing"
    }

    private fun String.evidencePrefix(): String =
        replace(" ", "")
            .replaceFirstChar { if (it.isLowerCase()) it.titlecase() else it.toString() }

    private companion object {
        val invalidTrustDecisions =
            setOf(
                EudiWalletTrustDecision.UNTRUSTED,
                EudiWalletTrustDecision.MISSING,
                EudiWalletTrustDecision.EXPIRED,
                EudiWalletTrustDecision.REVOKED,
                EudiWalletTrustDecision.UNSUPPORTED_PROFILE,
            )
    }
}
