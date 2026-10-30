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

package com.sphereon.sdjwt.vc

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.error.IdkError
import com.sphereon.sdjwt.KeyBindingJwt
import com.sphereon.sdjwt.SdJwtCompact
import com.sphereon.sdjwt.SdJwtVerificationResult
import com.sphereon.sdjwt.VerifySdJwtArgs
import com.sphereon.statuslist.CredentialStatusDecision
import com.sphereon.statuslist.CredentialStatusPolicy
import com.sphereon.statuslist.describeStatus
import com.sphereon.statuslist.evaluateCredentialStatus
import com.sphereon.statuslist.spi.CredentialStatusVerifier
import io.ktor.client.HttpClient
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * Default implementation of SD-JWT-VC verifier
 *
 * @property baseVerifier Base SD-JWT verifier (from command)
 * @property httpClient Ktor HTTP client for metadata resolution
 */
internal class SdJwtVcVerifierImpl(
    private val baseVerifier: suspend (VerifySdJwtArgs) -> IdkResult<SdJwtVerificationResult, IdkError>,
    private val httpClient: HttpClient,
    private val credentialStatusVerifiers: Set<CredentialStatusVerifier> = emptySet(),
) : SdJwtVcVerifier {
    override suspend fun verify(
        sdJwtString: String,
        opts: SdJwtVcVerificationOpts,
    ): IdkResult<SdJwtVcVerificationResult, SdJwtVcVerificationError> {
        // Step 1: Parse and verify base SD-JWT
        val baseArgs =
            VerifySdJwtArgs(
                sdJwt = sdJwtString,
                identifier = null, // Will be resolved from issuer metadata
                expectedAudience = null,
                expectedNonce = null,
                validateDisclosures = true,
            )

        val baseResult = baseVerifier(baseArgs)
        if (baseResult.isErr) {
            return IdkResult.err(
                SdJwtVcVerificationError.SdJwtVerificationFailed(
                    baseResult.error.message.defaultMessage,
                ),
            )
        }

        val verified = baseResult.value
        val fullPayload = verified.sdJwt.payload.fullPayload

        // Validate the IETF SD-JWT VC type; W3C `vc+sd-jwt` uses VCDM semantics.
        val typ = verified.sdJwt.type
        if (typ != SdJwtVcTypeHeaders.IETF_SD_JWT_VC) {
            return IdkResult.err(
                SdJwtVcVerificationError.InvalidTypeHeader(
                    "Invalid IETF SD-JWT VC typ header: expected '${SdJwtVcTypeHeaders.IETF_SD_JWT_VC}', got '$typ'",
                ),
            )
        }

        // Step 2: Extract and validate VCT claim
        val vct = SdJwtVcClaims.vct(fullPayload)
        if (vct.isNullOrBlank()) {
            return IdkResult.err(
                SdJwtVcVerificationError.InvalidVct("VCT claim is missing or empty"),
            )
        }

        // Step 3: Resolve issuer metadata (if needed)
        val issuer = fullPayload["iss"]?.jsonPrimitive?.content
        val issuerMetadata =
            if (issuer != null) {
                resolveIssuerMetadata(issuer, opts)
            } else {
                null
            }

        // Step 4: Resolve and validate type metadata (if enabled)
        val typeMetadata =
            if (opts.validateTypeMetadata) {
                val resolver = opts.typeMetadataResolver ?: UrlTypeMetadataResolver(httpClient)

                // Step 4a: Check for circular dependencies in extends chain (draft-13 §7.2.3)
                val circularCheck = validateTypeExtendsChain(vct, resolver)
                if (circularCheck != null) {
                    return IdkResult.err(
                        SdJwtVcVerificationError.TypeMetadataResolutionFailed(
                            (circularCheck as TypeMetadataResolutionResult.Failure).error,
                        ),
                    )
                }

                // Step 4b: Resolve type metadata
                when (val result = resolveTypeMetadata(vct, opts)) {
                    is TypeMetadataResolutionResult.Success -> {
                        result.metadata
                    }

                    is TypeMetadataResolutionResult.Failure -> {
                        return IdkResult.err(
                            SdJwtVcVerificationError.TypeMetadataResolutionFailed(result.error),
                        )
                    }
                }
            } else {
                null
            }

        // Step 5: Validate claims against type metadata
        if (typeMetadata != null) {
            val claimErrors =
                validateClaimRequirements(
                    credential = fullPayload,
                    metadata = typeMetadata,
                    disclosures = verified.sdJwt.payload.digestedDisclosures,
                )
            if (claimErrors.isNotEmpty()) {
                return IdkResult.err(
                    SdJwtVcVerificationError.TypeMetadataValidationFailed(claimErrors),
                )
            }
        }

        // Step 6: Check status (if enabled)
        if (opts.validateStatus) {
            val statusResult = checkStatus(fullPayload)
            if (statusResult != null) {
                return IdkResult.err(statusResult)
            }
        }

        return IdkResult.ok(
            SdJwtVcVerificationResult(
                sdJwt = verified.sdJwt,
                vct = vct,
                typeMetadata = typeMetadata,
                issuerMetadata = issuerMetadata,
            ),
        )
    }

    override suspend fun verifyPresentation(
        sdJwtString: String,
        expectedNonce: String?,
        opts: SdJwtVcVerificationOpts,
    ): IdkResult<SdJwtVcPresentationVerificationResult, SdJwtVcVerificationError> {
        // Step 1: Parse and verify base SD-JWT with KB-JWT
        val baseArgs =
            VerifySdJwtArgs(
                sdJwt = sdJwtString,
                identifier = null, // Will be resolved from issuer metadata
                expectedAudience = null,
                expectedNonce = expectedNonce,
                validateDisclosures = true,
            )

        val baseResult = baseVerifier(baseArgs)
        if (baseResult.isErr) {
            return IdkResult.err(
                SdJwtVcVerificationError.SdJwtVerificationFailed(
                    baseResult.error.message.defaultMessage,
                ),
            )
        }

        val verified = baseResult.value
        val fullPayload = verified.sdJwt.payload.fullPayload

        // Validate the IETF SD-JWT VC type; W3C `vc+sd-jwt` uses VCDM semantics.
        val typ = verified.sdJwt.type
        if (typ != SdJwtVcTypeHeaders.IETF_SD_JWT_VC) {
            return IdkResult.err(
                SdJwtVcVerificationError.InvalidTypeHeader(
                    "Invalid IETF SD-JWT VC typ header: expected '${SdJwtVcTypeHeaders.IETF_SD_JWT_VC}', got '$typ'",
                ),
            )
        }

        // Step 2: Extract KB-JWT
        val kbJwt = verified.sdJwt.keyBindingJwt
        if (kbJwt == null) {
            return IdkResult.err(
                SdJwtVcVerificationError.SdJwtVerificationFailed(
                    "Key Binding JWT is required for presentation verification",
                ),
            )
        }

        // Step 3: Extract and validate VCT claim
        val vct = SdJwtVcClaims.vct(fullPayload)
        if (vct.isNullOrBlank()) {
            return IdkResult.err(
                SdJwtVcVerificationError.InvalidVct("VCT claim is missing or empty"),
            )
        }

        // Step 4: Resolve issuer metadata (if needed)
        val issuer = fullPayload["iss"]?.jsonPrimitive?.content
        val issuerMetadata =
            if (issuer != null) {
                resolveIssuerMetadata(issuer, opts)
            } else {
                null
            }

        // Step 5: Resolve and validate type metadata (if enabled)
        val typeMetadata =
            if (opts.validateTypeMetadata) {
                val resolver = opts.typeMetadataResolver ?: UrlTypeMetadataResolver(httpClient)

                // Step 5a: Check for circular dependencies in extends chain (draft-13 §7.2.3)
                val circularCheck = validateTypeExtendsChain(vct, resolver)
                if (circularCheck != null) {
                    return IdkResult.err(
                        SdJwtVcVerificationError.TypeMetadataResolutionFailed(
                            (circularCheck as TypeMetadataResolutionResult.Failure).error,
                        ),
                    )
                }

                // Step 5b: Resolve type metadata
                when (val result = resolveTypeMetadata(vct, opts)) {
                    is TypeMetadataResolutionResult.Success -> {
                        result.metadata
                    }

                    is TypeMetadataResolutionResult.Failure -> {
                        return IdkResult.err(
                            SdJwtVcVerificationError.TypeMetadataResolutionFailed(result.error),
                        )
                    }
                }
            } else {
                null
            }

        // Step 6: Validate claims against type metadata
        if (typeMetadata != null) {
            val claimErrors =
                validateClaimRequirements(
                    credential = fullPayload,
                    metadata = typeMetadata,
                    disclosures = verified.sdJwt.payload.digestedDisclosures,
                )
            if (claimErrors.isNotEmpty()) {
                return IdkResult.err(
                    SdJwtVcVerificationError.TypeMetadataValidationFailed(claimErrors),
                )
            }
        }

        // Step 7: Check status (if enabled)
        if (opts.validateStatus) {
            val statusResult = checkStatus(fullPayload)
            if (statusResult != null) {
                return IdkResult.err(statusResult)
            }
        }

        return IdkResult.ok(
            SdJwtVcPresentationVerificationResult(
                sdJwt = verified.sdJwt,
                kbJwt = kbJwt,
                vct = vct,
                typeMetadata = typeMetadata,
                issuerMetadata = issuerMetadata,
            ),
        )
    }

    // Private helper methods

    private suspend fun resolveTypeMetadata(
        vct: String,
        opts: SdJwtVcVerificationOpts,
    ): TypeMetadataResolutionResult {
        val resolver =
            opts.typeMetadataResolver
                ?: UrlTypeMetadataResolver(httpClient)

        return resolver.resolve(vct)
    }

    private suspend fun resolveIssuerMetadata(
        issuer: String,
        opts: SdJwtVcVerificationOpts,
    ): SdJwtVcIssuerMetadata? {
        val resolver =
            opts.issuerMetadataResolver
                ?: WellKnownIssuerMetadataResolver(httpClient)

        return when (val result = resolver.resolve(issuer)) {
            is IssuerMetadataResolutionResult.Success -> result.metadata
            is IssuerMetadataResolutionResult.Failure -> null
        }
    }

    /**
     * Checks the credential's status against the configured [credentialStatusVerifiers] (IETF Token
     * Status List, W3C Bitstring, ...) under the strict default policy (reject revoked/suspended, fail
     * closed). Returns null when no verifiers are wired, the credential carries no recognized status
     * reference, or the status is acceptable; otherwise a [SdJwtVcVerificationError.StatusCheckFailed].
     *
     * Shares the OID4VP verifier's status mechanism ([evaluateCredentialStatus] over the pluggable
     * [CredentialStatusVerifier] set) so SD-JWT VC verification gains every status format the set
     * supports instead of a hand-rolled Token-Status-List-only path.
     */
    private suspend fun checkStatus(payload: JsonObject): SdJwtVcVerificationError? {
        if (credentialStatusVerifiers.isEmpty()) return null
        val evaluation = evaluateCredentialStatus(credentialStatusVerifiers, payload, CredentialStatusPolicy())
        if (evaluation.decision != CredentialStatusDecision.REJECT) return null
        val word = evaluation.rejectedStatus?.let { describeStatus(it) }
        return SdJwtVcVerificationError.StatusCheckFailed(
            if (word != null) "credential is $word" else (evaluation.reason ?: "credential status not accepted"),
        )
    }
}
