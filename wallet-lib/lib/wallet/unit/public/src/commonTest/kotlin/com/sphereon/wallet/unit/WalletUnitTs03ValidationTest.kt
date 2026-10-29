/*
 * Copyright 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

package com.sphereon.wallet.unit

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.decodeFromBase64Url
import com.sphereon.core.api.encodeToBase64Url
import com.sphereon.core.api.error.IdkError
import com.sphereon.wallet.unit.attestation.KeyAttestationValidationRequest
import com.sphereon.wallet.unit.attestation.LocalEvaluationWalletAttestationSigner
import com.sphereon.wallet.unit.attestation.Oid4vciKeyAttestationClaims
import com.sphereon.wallet.unit.attestation.Ts03JoseVerificationEvidence
import com.sphereon.wallet.unit.attestation.Ts03JoseVerificationRequest
import com.sphereon.wallet.unit.attestation.Ts03JoseVerifier
import com.sphereon.wallet.unit.attestation.Ts03JwtHeader
import com.sphereon.wallet.unit.attestation.Ts03KeyAttestationClaims
import com.sphereon.wallet.unit.attestation.Ts03KeyStorageClaim
import com.sphereon.wallet.unit.attestation.Ts03StatusClaim
import com.sphereon.wallet.unit.attestation.Ts03UserAuthenticationClaim
import com.sphereon.wallet.unit.attestation.Ts03WalletAttestationEncoder
import com.sphereon.wallet.unit.attestation.Ts03WalletAttestationValidationPolicy
import com.sphereon.wallet.unit.attestation.Ts03WalletAttestationValidator
import com.sphereon.wallet.unit.attestation.Ts03WalletInstanceAttestationClaims
import com.sphereon.wallet.unit.attestation.WalletAttestationSignerProfile
import com.sphereon.wallet.unit.attestation.WalletAttestationSigningAlgorithm
import com.sphereon.wallet.unit.attestation.WalletAttestationSigningRequest
import com.sphereon.wallet.unit.attestation.WalletInstanceAttestationValidationRequest
import com.sphereon.wallet.unit.attestation.WalletUnitAttestationFormat
import com.sphereon.wallet.unit.attestation.WalletUnitAttestationMaterial
import com.sphereon.wallet.unit.attestation.WalletUnitAttestationTrustInput
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class WalletUnitTs03ValidationTest {
    private val json =
        Json {
            encodeDefaults = false
            explicitNulls = false
        }
    private val validator = Ts03WalletAttestationValidator(joseVerifier = AcceptingJoseVerifier)

    @Test
    fun encodesOid4vciKeyAttestationWithPublicClaimsSerializer() =
        runTest {
            val claims =
                Oid4vciKeyAttestationClaims(
                    iss = ISSUER,
                    iat = 1_800_000_000L,
                    exp = 1_800_000_300L,
                    nonce = NONCE,
                    attestedKeys =
                        listOf(
                            JsonObject(
                                mapOf(
                                    "kty" to JsonPrimitive("EC"),
                                    "crv" to JsonPrimitive("P-256"),
                                    "x" to JsonPrimitive("x"),
                                    "y" to JsonPrimitive("y"),
                                ),
                            ),
                        ),
                )
            val encoded =
                Ts03WalletAttestationEncoder()
                    .encodeOid4vciKeyAttestation(
                        claims = claims,
                        signer = LocalEvaluationWalletAttestationSigner(signerId = "signer-a"),
                        signingRequest = signingRequest(listOf("certificate-chain-a")),
                    ).value

            val header =
                json
                    .parseToJsonElement(encoded.compact.substringBefore('.').decodeFromBase64Url().decodeToString())
                    .jsonObject
            assertTrue(header["typ"]?.toString() == "\"key-attestation+jwt\"")
        }

    @Test
    fun validatesWiaFixtureWithTrustEvidence() =
        runTest {
            val now = 1_800_000_000L
            val result =
                validator
                    .validateWalletInstanceAttestation(
                        WalletInstanceAttestationValidationRequest(
                            material = WalletUnitAttestationMaterial(WalletUnitAttestationFormat.JWT, wiaJwt(now)),
                            expectedAudience = AUDIENCE,
                            expectedIssuer = ISSUER,
                            trust = trustInput(now, statusListUri = WIA_STATUS_URI),
                            validationPolicy = Ts03WalletAttestationValidationPolicy.walletProviderTrustList(),
                            validationTimeEpochSeconds = now,
                            clockSkewSeconds = 0,
                        ),
                    ).value

            assertTrue(result.valid, result.errors.joinToString())
            assertTrue(result.evidence["client_statusUri"] == WIA_STATUS_URI)
        }

    @Test
    fun validatesKaFixtureWithTrustEvidence() =
        runTest {
            val now = 1_800_000_000L
            val result =
                validator
                    .validateKeyAttestation(
                        KeyAttestationValidationRequest(
                            material = WalletUnitAttestationMaterial(WalletUnitAttestationFormat.KEY_ATTESTATION_JWT, kaJwt(now)),
                            expectedAudience = AUDIENCE,
                            expectedIssuer = ISSUER,
                            expectedNonce = NONCE,
                            requiredKeyStorage = listOf("ISO_18045_HIGH"),
                            requiredUserAuthentication = listOf("high"),
                            trust = trustInput(now, statusListUri = KA_STATUS_URI, statusIndex = "2"),
                            validationPolicy = Ts03WalletAttestationValidationPolicy.walletProviderTrustList(),
                            validationTimeEpochSeconds = now,
                            clockSkewSeconds = 0,
                        ),
                    ).value

            assertTrue(result.valid, result.errors.joinToString())
            assertTrue(result.evidence["key_storage_statusUri"] == KA_STATUS_URI)
        }

    @Test
    fun missingX5cFailsClosed() =
        runTest {
            val now = 1_800_000_000L
            val result =
                validator
                    .validateWalletInstanceAttestation(
                        WalletInstanceAttestationValidationRequest(
                            material = WalletUnitAttestationMaterial(WalletUnitAttestationFormat.JWT, wiaJwt(now, x5c = emptyList())),
                            expectedAudience = AUDIENCE,
                            trust = trustInput(now, statusListUri = WIA_STATUS_URI),
                            validationPolicy = Ts03WalletAttestationValidationPolicy.walletProviderTrustList(),
                            validationTimeEpochSeconds = now,
                            clockSkewSeconds = 0,
                        ),
                    ).value

            assertFalse(result.valid)
            assertTrue(result.errors.any { it.contains("x5c") })
        }

    @Test
    fun wrongWiaAudienceFailsClosed() =
        runTest {
            val now = 1_800_000_000L
            val result =
                validator
                    .validateWalletInstanceAttestation(
                        WalletInstanceAttestationValidationRequest(
                            material = WalletUnitAttestationMaterial(WalletUnitAttestationFormat.JWT, wiaJwt(now)),
                            expectedAudience = "wrong-audience",
                            trust = trustInput(now, statusListUri = WIA_STATUS_URI),
                            validationPolicy = Ts03WalletAttestationValidationPolicy.walletProviderTrustList(),
                            validationTimeEpochSeconds = now,
                            clockSkewSeconds = 0,
                        ),
                    ).value

            assertFalse(result.valid)
            assertTrue(result.errors.any { it.contains("audience") })
        }

    @Test
    fun expiredWiaFailsClosedSeparatelyFromStatusMaintenance() =
        runTest {
            val now = 1_800_000_000L
            val result =
                validator
                    .validateWalletInstanceAttestation(
                        WalletInstanceAttestationValidationRequest(
                            material = WalletUnitAttestationMaterial(WalletUnitAttestationFormat.JWT, wiaJwt(now, expiresAt = now - 1, statusExpiresAt = now + 600)),
                            expectedAudience = AUDIENCE,
                            trust = trustInput(now, statusListUri = WIA_STATUS_URI),
                            validationPolicy = Ts03WalletAttestationValidationPolicy.walletProviderTrustList(),
                            validationTimeEpochSeconds = now,
                            clockSkewSeconds = 0,
                        ),
                    ).value

            assertFalse(result.valid)
            assertTrue(result.errors.any { it.contains("technical expiry") })
            assertFalse(result.errors.any { it.contains("maintenance expiry") })
        }

    @Test
    fun staleStatusMaintenanceEvidenceFailsClosedSeparatelyFromTechnicalExpiry() =
        runTest {
            val now = 1_800_000_000L
            val result =
                validator
                    .validateWalletInstanceAttestation(
                        WalletInstanceAttestationValidationRequest(
                            material = WalletUnitAttestationMaterial(WalletUnitAttestationFormat.JWT, wiaJwt(now, expiresAt = now + 300, statusExpiresAt = now + 600)),
                            expectedAudience = AUDIENCE,
                            trust = trustInput(now, statusListUri = WIA_STATUS_URI, statusMaintenanceExpiresAt = now - 1),
                            validationPolicy = Ts03WalletAttestationValidationPolicy.walletProviderTrustList(),
                            validationTimeEpochSeconds = now,
                            clockSkewSeconds = 0,
                        ),
                    ).value

            assertFalse(result.valid)
            assertFalse(result.errors.any { it.contains("technical expiry") })
            assertTrue(result.errors.any { it.contains("status evidence maintenance expiry") })
        }

    @Test
    fun revokedStatusEvidenceFailsClosed() =
        runTest {
            val now = 1_800_000_000L
            val result =
                validator
                    .validateWalletInstanceAttestation(
                        WalletInstanceAttestationValidationRequest(
                            material = WalletUnitAttestationMaterial(WalletUnitAttestationFormat.JWT, wiaJwt(now)),
                            expectedAudience = AUDIENCE,
                            trust = trustInput(now, statusListUri = WIA_STATUS_URI, statusRevoked = true),
                            validationPolicy = Ts03WalletAttestationValidationPolicy.walletProviderTrustList(),
                            validationTimeEpochSeconds = now,
                            clockSkewSeconds = 0,
                        ),
                    ).value

            assertFalse(result.valid)
            assertTrue(result.errors.any { it.contains("revoked") })
        }

    @Test
    fun wrongKaNonceAndKeyStoragePolicyFailClosed() =
        runTest {
            val now = 1_800_000_000L
            val result =
                validator
                    .validateKeyAttestation(
                        KeyAttestationValidationRequest(
                            material =
                                WalletUnitAttestationMaterial(
                                    WalletUnitAttestationFormat.KEY_ATTESTATION_JWT,
                                    kaJwt(now, nonce = "wrong-nonce", keyStorageSecurityLevel = "ISO_18045_BASIC"),
                                ),
                            expectedAudience = AUDIENCE,
                            expectedIssuer = ISSUER,
                            expectedNonce = NONCE,
                            requiredKeyStorage = listOf("ISO_18045_HIGH"),
                            requiredUserAuthentication = listOf("high"),
                            trust = trustInput(now, statusListUri = KA_STATUS_URI, statusIndex = "2"),
                            validationPolicy = Ts03WalletAttestationValidationPolicy.walletProviderTrustList(),
                            validationTimeEpochSeconds = now,
                            clockSkewSeconds = 0,
                        ),
                    ).value

            assertFalse(result.valid)
            assertTrue(result.errors.any { it.contains("c_nonce") })
            assertTrue(result.errors.any { it.contains("key_storage.security_level") })
        }

    @Test
    fun unsupportedAlgorithmFailsClosed() =
        runTest {
            val now = 1_800_000_000L
            val result =
                validator
                    .validateWalletInstanceAttestation(
                        WalletInstanceAttestationValidationRequest(
                            material = WalletUnitAttestationMaterial(WalletUnitAttestationFormat.JWT, compactJwt("HS256", json.encodeToString(wiaClaims(now)))),
                            expectedAudience = AUDIENCE,
                            trust = trustInput(now, statusListUri = WIA_STATUS_URI),
                            validationPolicy = Ts03WalletAttestationValidationPolicy.walletProviderTrustList(),
                            validationTimeEpochSeconds = now,
                            clockSkewSeconds = 0,
                        ),
                    ).value

            assertFalse(result.valid)
            assertTrue(result.errors.any { it.contains("Unsupported TS03 signing algorithm") })
        }

    @Test
    fun untrustedProviderEvidenceFailsClosed() =
        runTest {
            val now = 1_800_000_000L
            val result =
                validator
                    .validateWalletInstanceAttestation(
                        WalletInstanceAttestationValidationRequest(
                            material = WalletUnitAttestationMaterial(WalletUnitAttestationFormat.JWT, wiaJwt(now)),
                            expectedAudience = AUDIENCE,
                            trust = trustInput(now, statusListUri = WIA_STATUS_URI, providerTrusted = false),
                            validationPolicy = Ts03WalletAttestationValidationPolicy.walletProviderTrustList(),
                            validationTimeEpochSeconds = now,
                            clockSkewSeconds = 0,
                        ),
                    ).value

            assertFalse(result.valid)
            assertTrue(result.errors.any { it.contains("Wallet Provider trust evidence is not trusted") })
        }

    @Test
    fun missingProductionEvidenceFailsClosed() =
        runTest {
            val now = 1_800_000_000L
            val result =
                validator
                    .validateWalletInstanceAttestation(
                        WalletInstanceAttestationValidationRequest(
                            material = WalletUnitAttestationMaterial(WalletUnitAttestationFormat.JWT, wiaJwt(now)),
                            expectedAudience = AUDIENCE,
                            validationPolicy = Ts03WalletAttestationValidationPolicy.walletProviderTrustList(),
                            validationTimeEpochSeconds = now,
                            clockSkewSeconds = 0,
                        ),
                    ).value

            assertFalse(result.valid)
            assertTrue(result.errors.any { it.contains("trust evidence is missing") })
            assertTrue(result.errors.any { it.contains("status evidence is missing") })
        }

    @Test
    fun unsupportedSignerProfileEvidenceFailsClosed() =
        runTest {
            val now = 1_800_000_000L
            val result =
                validator
                    .validateWalletInstanceAttestation(
                        WalletInstanceAttestationValidationRequest(
                            material = WalletUnitAttestationMaterial(WalletUnitAttestationFormat.JWT, wiaJwt(now)),
                            expectedAudience = AUDIENCE,
                            trust =
                                trustInput(
                                    now,
                                    statusListUri = WIA_STATUS_URI,
                                    providerDecision = EudiWalletTrustDecision.UNSUPPORTED_PROFILE,
                                ),
                            validationPolicy = Ts03WalletAttestationValidationPolicy.walletProviderTrustList(),
                            validationTimeEpochSeconds = now,
                            clockSkewSeconds = 0,
                        ),
                    ).value

            assertFalse(result.valid)
            assertTrue(result.errors.any { it.contains("not trusted") })
        }

    private suspend fun wiaJwt(
        now: Long,
        expiresAt: Long = now + 300,
        statusExpiresAt: Long = now + 600,
        x5c: List<String> = listOf("certificate-chain-a"),
    ): String =
        Ts03WalletAttestationEncoder()
            .encodeWalletInstanceAttestation(
                claims = wiaClaims(now, expiresAt, statusExpiresAt),
                signer = LocalEvaluationWalletAttestationSigner(signerId = "signer-a"),
                signingRequest = signingRequest(x5c),
            ).value.compact

    private suspend fun kaJwt(
        now: Long,
        nonce: String = NONCE,
        keyStorageSecurityLevel: String = "ISO_18045_HIGH",
        statusExpiresAt: Long = now + 600,
    ): String =
        Ts03WalletAttestationEncoder()
            .encodeKeyAttestation(
                claims =
                    Ts03KeyAttestationClaims(
                        iss = ISSUER,
                        sub = "wallet-unit-a",
                        aud = AUDIENCE,
                        iat = now,
                        exp = now + 300,
                        jti = "ka-jti-a",
                        attestedKeys = listOf(WalletAttestedKeyRef(keyId = "key-a", algorithm = "ES256")),
                        certification = mapOf("certification_id" to "secure-component-cert-a"),
                        keyStorage =
                            Ts03KeyStorageClaim(
                                securityLevel = keyStorageSecurityLevel,
                                secureComponent = "REMOTE_WSCD",
                                nonExportable = true,
                            ),
                        userAuthentication = Ts03UserAuthenticationClaim(assuranceLevel = "high", methods = listOf("pin")),
                        keyStorageStatus = Ts03StatusClaim(status = "$KA_STATUS_URI#2", exp = statusExpiresAt),
                        cNonce = nonce,
                    ),
                signer = LocalEvaluationWalletAttestationSigner(signerId = "signer-a"),
                signingRequest = signingRequest(listOf("certificate-chain-a")),
            ).value.compact

    private fun wiaClaims(
        now: Long,
        expiresAt: Long = now + 300,
        statusExpiresAt: Long = now + 600,
    ): Ts03WalletInstanceAttestationClaims =
        Ts03WalletInstanceAttestationClaims(
            iss = ISSUER,
            sub = "wallet-instance-a",
            aud = AUDIENCE,
            iat = now,
            exp = expiresAt,
            jti = "wia-jti-a",
            walletName = "wallet-solution-a",
            walletVersion = "1.0",
            walletSolutionCertificationInformation = mapOf("certification_id" to "cert-a"),
            clientStatus = Ts03StatusClaim(status = "$WIA_STATUS_URI#1", exp = statusExpiresAt),
        )

    private fun trustInput(
        now: Long,
        statusListUri: String,
        statusIndex: String = "1",
        statusRevoked: Boolean = false,
        statusMaintenanceExpiresAt: Long? = now + 600,
        providerTrusted: Boolean = true,
        providerDecision: EudiWalletTrustDecision = EudiWalletTrustDecision.TRUSTED,
    ): WalletUnitAttestationTrustInput =
        WalletUnitAttestationTrustInput(
            walletProviderTrustEvidence =
                EudiWalletTrustEvidence(
                    trusted = providerTrusted,
                    decision = providerDecision,
                    trustListUri = "https://trust.example/lote",
                    trustAnchor = "trust-anchor-a",
                    matchedCertificateFingerprint = "sha256:abc",
                    signingCertificateProfile = "ETSI_TS_119_412_6_WALLET_PROVIDER",
                    expiresAtEpochSeconds = now + 600,
                ),
            walletSolutionTrustEvidence =
                EudiWalletTrustEvidence(
                    trusted = true,
                    decision = EudiWalletTrustDecision.TRUSTED,
                    trustListUri = "https://trust.example/lote",
                    walletSolutionName = "wallet-solution-a",
                    walletSolutionVersion = "1.0",
                    expiresAtEpochSeconds = now + 600,
                ),
            statusEvidence =
                WalletAttestationStatusEvidence(
                    statusListUri = statusListUri,
                    index = statusIndex,
                    revoked = statusRevoked,
                    maintenanceExpiresAtEpochSeconds = statusMaintenanceExpiresAt,
                ),
        )

    private fun signingRequest(x5c: List<String>): WalletAttestationSigningRequest =
        WalletAttestationSigningRequest(
            algorithm = WalletAttestationSigningAlgorithm.ES256,
            signerProfile = WalletAttestationSignerProfile.LOCAL_EVALUATION,
            signerId = "signer-a",
            signingInput = ByteArray(0),
            x5c = x5c,
            keyId = "kid-a",
        )

    private fun compactJwt(
        alg: String,
        payloadJson: String
    ): String {
        val header = json.encodeToString(Ts03JwtHeader(alg = alg, x5c = listOf("certificate-chain-a")))
        return listOf(header, payloadJson, "signature")
            .joinToString(".") { it.encodeToByteArray().encodeToBase64Url() }
    }

    private object AcceptingJoseVerifier : Ts03JoseVerifier {
        override suspend fun verify(request: Ts03JoseVerificationRequest): IdkResult<Ts03JoseVerificationEvidence, IdkError> =
            Ok(
                Ts03JoseVerificationEvidence(
                    valid = true,
                    signerKeyId = "kid-a",
                    signerFingerprint = "sha256:abc",
                    evidence = mapOf("jose" to "verified"),
                ),
            )
    }

    private companion object {
        const val ISSUER = "https://wallet-provider.example"
        const val AUDIENCE = "issuer-audience"
        const val NONCE = "nonce-a"
        const val WIA_STATUS_URI = "https://status.example/wia"
        const val KA_STATUS_URI = "https://status.example/ka"
    }
}
