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

package com.sphereon.openid.oid4vp.verifier.impl

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.decodeFromBase64Url
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.service.TypedServiceCommandAdapter
import com.sphereon.crypto.jose.jws.JwsCompact
import com.sphereon.crypto.jose.jws.command.VerifyJwsArgs
import com.sphereon.crypto.jose.jws.command.VerifyJwsCommand
import com.sphereon.crypto.resolution.IdentifierMethodDefaults
import com.sphereon.crypto.resolution.extern.ExternalIdentifierDidOpts
import com.sphereon.did.models.VerificationPurpose
import com.sphereon.did.resolver.DidResolutionOptions
import com.sphereon.did.resolver.DidResolverRegistry
import com.sphereon.di.session.SessionScope
import com.sphereon.mdoc.data.DeviceAuthValidation
import com.sphereon.mdoc.data.MdocVerification
import com.sphereon.mdoc.data.MdocValidations
import com.sphereon.mdoc.data.device.DeviceResponseCborCodec
import com.sphereon.mdoc.data.device.DocumentResponseEncryptionProviderResolver
import com.sphereon.mdoc.data.device.ZkProofProviderResolver
import com.sphereon.mdoc.oid4vp.Oid4vpDeviceAuthenticationContext
import com.sphereon.mdoc.oid4vp.toSessionTranscript
import com.sphereon.mdoc.transfer.reader.SessionTranscript
import com.sphereon.openid.oid4vp.common.CredentialFormat
import com.sphereon.openid.oid4vc.common.vcdm.VcdmClassifier
import com.sphereon.openid.oid4vc.common.vcdm.VcdmDocumentKind
import com.sphereon.openid.oid4vc.common.vcdm.VcdmProfiles
import com.sphereon.openid.oid4vc.common.vcdm.VcdmVersion
import com.sphereon.openid.oid4vp.verifier.CredentialIssuerControllerClaim
import com.sphereon.openid.oid4vp.verifier.HolderBindingResult
import com.sphereon.openid.oid4vp.verifier.TrustedAuthenticationResolution
import com.sphereon.openid.oid4vp.verifier.TrustedAuthenticationPurpose
import com.sphereon.openid.oid4vp.verifier.VerifyHolderBindingArgs
import com.sphereon.openid.oid4vp.verifier.VerifyHolderBindingCommand
import com.sphereon.sdjwt.VerifySdJwtArgs
import com.sphereon.sdjwt.command.VerifySdJwtCommand
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.Provider
import dev.zacsweers.metro.SingleIn
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.jsonObject
import kotlin.time.Clock

import dev.zacsweers.metro.ExposeImplBinding
/**
 * Implementation of VerifyHolderBindingCommand for OpenID4VP RP (Verifier).
 *
 * Verifies cryptographic holder binding in VP tokens per OpenID4VP 1.0 Final Section 7.3:
 * - SD-JWT: Verifies KB-JWT signature using cnf claim, validates nonce/aud/sd_hash
 * - mDoc: Verifies DeviceAuth COSE signature over SessionTranscript
 * - JWT VP: Verifies JWT signature and validates nonce/aud claims
 *
 * This implementation integrates with the existing SD-JWT verification infrastructure
 * in `libraries/sdjwt` which provides full RFC 9901 compliant KB-JWT verification.
 */
@Inject
@SingleIn(SessionScope::class)
@ExposeImplBinding
class VerifyHolderBindingCommandImpl(
    execution: SessionExecution,
    private val verifySdJwtCommand: VerifySdJwtCommand,
    private val verifyJwsCommand: VerifyJwsCommand,
    private val mdocValidations: MdocValidations,
    private val deviceAuthValidation: DeviceAuthValidation,
    private val deviceResponseCborCodec: DeviceResponseCborCodec,
    // Optional contributed binding: Provider<T>? (a bare T? = null stays null in this Metro setup).
    // Without it a DID issuer's assertionMethod cannot be checked and DID-issued SD-JWTs are refused.
    private val didResolverRegistryProvider: Provider<DidResolverRegistry>? = null,
) : TypedServiceCommandAdapter<VerifyHolderBindingArgs, HolderBindingResult, IdkError>(
        commandId = VerifyHolderBindingCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<VerifyHolderBindingArgs>(),
        outputTypeToken = typeToken<HolderBindingResult>(),
    ),
    VerifyHolderBindingCommand {
    override val commandId: String get() = VerifyHolderBindingCommand.COMMAND_ID

    override suspend fun supports(args: Any): Boolean = args is VerifyHolderBindingArgs

    private val json = Json { ignoreUnknownKeys = true }

    override suspend fun doExecute(
        args: VerifyHolderBindingArgs,
        applyDuring: (VerifyHolderBindingArgs) -> VerifyHolderBindingArgs,
    ): IdkResult<HolderBindingResult, IdkError> {
        val processedArgs = applyDuring(args)

        log.debug("Verifying holder binding for credentialFormat=${processedArgs.credentialFormat}, presentationFormat=${processedArgs.presentationFormat}")

        val presentation = processedArgs.presentation
        val expectedNonce = processedArgs.expectedNonce
        val expectedAudience = processedArgs.expectedAudience
        val credentialFormat = processedArgs.credentialFormat

        // Compact JWS inputs are classified from their protected header and payload before
        // caller-supplied format routing. A three-part JWT-shaped string is not sufficient to
        // authorize JWT-VP holder binding, and a credential must never be treated as a VP.
        if (!presentation.contains('~') && presentation.contains('.')) {
            val classificationResult = VcdmClassifier.classifyCompactJws(presentation)
            if (classificationResult.isErr) {
                return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        causes = listOf(classificationResult.error),
                        message =
                            "Compact JWS failed strict VCDM classification: " +
                                classificationResult.error.message.defaultMessage,
                    ),
                )
            }
            val classification = classificationResult.value
            if (classification.document.kind != VcdmDocumentKind.PRESENTATION) {
                return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message = "A VCDM credential is not a holder-bound presentation",
                    ),
                )
            }
            if (classification.presentationFormat != processedArgs.presentationFormat) {
                return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message =
                            "Declared presentation format ${processedArgs.presentationFormat?.value} does not match " +
                                "classified VCDM presentation format ${classification.presentationFormat?.value}",
                    ),
                )
            }
            val profileValidation =
                when (classification.document.version) {
                    VcdmVersion.V1_1 -> VcdmProfiles.v1_1.validatePresentation(classification.document.json)
                    VcdmVersion.V2_0 -> VcdmProfiles.v2_0.validatePresentation(classification.document.json)
                    else -> null
                }
            if (profileValidation == null || !profileValidation.valid) {
                return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message = "Compact JWS presentation does not conform to its VCDM profile",
                    ),
                )
            }
            return verifyJwtVpHolderBinding(
                presentation = presentation,
                expectedNonce = expectedNonce,
                expectedAudience = expectedAudience,
                trustedAuthentications = processedArgs.trustedAuthentications,
                classification = classification,
            )
        }

        return when {
            credentialFormat?.isSdJwt == true -> {
                verifySdJwtHolderBinding(
                    presentation = presentation,
                    expectedNonce = expectedNonce,
                    expectedAudience = expectedAudience,
                    requireCryptographicHolderBinding = processedArgs.requireCryptographicHolderBinding,
                    trustedAuthentications = processedArgs.trustedAuthentications,
                )
            }

            credentialFormat?.isMdoc == true -> {
                verifyMdocHolderBinding(
                    presentation = presentation,
                    expectedNonce = expectedNonce,
                    clientId = processedArgs.clientId,
                    responseUri = processedArgs.responseUri,
                    responseMode = processedArgs.responseMode,
                    callerOrigin = processedArgs.callerOrigin,
                    expectedMdocDocumentType = processedArgs.expectedMdocDocumentType,
                    verifierEncryptionJwkThumbprint = processedArgs.verifierEncryptionJwkThumbprint,
                    expectedZkRequests = processedArgs.mdocZkRequests,
                    zkProofProviders = processedArgs.mdocZkProofProviders,
                    documentResponseDecryptionKey = processedArgs.mdocDocumentResponseDecryptionKey,
                    documentResponseEncryptionParameters = processedArgs.mdocDocumentResponseEncryptionParameters,
                    documentResponseEncryptionProviders = processedArgs.mdocDocumentResponseEncryptionProviders,
                    iso18013MdocGeneratedNonce = processedArgs.iso18013MdocGeneratedNonce,
                )
            }

            credentialFormat?.isJwtVc == true -> {
                Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message =
                            "A compact VCDM presentation is required for JWT holder binding verification",
                    ),
                )
            }

            else -> {
                Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message = "Unsupported credential format for holder binding verification: ${credentialFormat?.value}",
                    ),
                )
            }
        }
    }

    /**
     * Verify holder binding in SD-JWT using KB-JWT.
     *
     * Uses the existing SD-JWT verification infrastructure which implements RFC 9901:
     * - Verifies KB-JWT signature using cnf.jwk from issuer JWT
     * - Validates aud claim matches expected audience
     * - Validates nonce claim matches expected nonce
     * - Validates sd_hash matches hash of SD-JWT without KB-JWT
     * - Validates iat claim is present
     */
    private suspend fun verifySdJwtHolderBinding(
        presentation: String,
        expectedNonce: String,
        expectedAudience: String,
        requireCryptographicHolderBinding: Boolean,
        trustedAuthentications: List<TrustedAuthenticationResolution>,
    ): IdkResult<HolderBindingResult, IdkError> {
        log.debug("Verifying SD-JWT holder binding with KB-JWT verification")

        val issuer = sdJwtIssuer(presentation)
        val matchingSources = trustedAuthentications.filter {
            it.purpose == TrustedAuthenticationPurpose.CREDENTIAL_ISSUER &&
                it.controllerClaim == CredentialIssuerControllerClaim.ISSUER &&
                it.controller == issuer
        }
        if (matchingSources.size > 1) {
            return holderBindingFailure("multiple configured issuer authentication sources match controller '$issuer'")
        }
        val configuredSource = matchingSources.singleOrNull()
        if (!issuer.isNullOrBlank() && !issuer.startsWith("did:") && configuredSource == null) {
            return holderBindingFailure("non-DID SD-JWT issuer '$issuer' requires an exact configured authentication source")
        }
        // DIIP v5 Appendix B: a credential issued under a DID that names its Issuer's OpenID Federation
        // entity in `fed` is admitted with that entity's `vc_issuer` keys, unless the DID itself is admitted.
        val federated = FederatedCredentialIssuer.applicableSources(issuer, sdJwtIssuerPayload(presentation), trustedAuthentications)
        if (federated != null) {
            return verifySdJwtWithFederationEntity(
                presentation, issuer!!, federated, expectedNonce, expectedAudience, requireCryptographicHolderBinding,
            )
        }

        // The issuer JWT is untrusted until its signature has been verified.  The generic JWS
        // resolver intentionally supports header-driven jwk/x5c/jku resolution for standalone
        // JOSE callers, but that is not an issuer trust decision: a presented SD-JWT must not be
        // able to select its own issuer key.  DID issuers may still resolve through their `kid`
        // via the configured DID resolver; embedded/remote JOSE key material is never an
        // alternative trust source.  An x5c chain is accepted only when it exactly matches an
        // already-admitted verifier X.509 source.
        val issuerHeader = sdJwtIssuerHeader(presentation)
            ?: return holderBindingFailure("SD-JWT issuer JWT protected header is malformed")
        val headerIssuerElement = issuerHeader["iss"]
        if (headerIssuerElement != null) {
            val headerIssuer = (headerIssuerElement as? JsonPrimitive)?.takeIf { it.isString }?.content
            if (headerIssuer.isNullOrBlank() || headerIssuer != issuer) {
                return holderBindingFailure("SD-JWT issuer JWT protected-header iss must agree with the issuer claim")
            }
        }
        val forbiddenIssuerKeyClaim = listOf("jwk", "jku", "x5u").firstOrNull(issuerHeader::containsKey)
        if (forbiddenIssuerKeyClaim != null) {
            val keyDescription = if (forbiddenIssuerKeyClaim == "jwk") "embedded jwk" else "'$forbiddenIssuerKeyClaim'"
            return holderBindingFailure("SD-JWT issuer JWT header $keyDescription cannot be used as a trust anchor")
        }
        val x5cElement = issuerHeader["x5c"]
        if (x5cElement != null &&
            (x5cElement !is JsonArray || x5cElement.isEmpty() ||
                x5cElement.any { it !is JsonPrimitive || !it.isString || it.content.isBlank() })
        ) {
            return holderBindingFailure("SD-JWT issuer JWT header 'x5c' must be a non-empty array of certificate strings")
        }
        val issuerX5c = (x5cElement as? JsonArray).orEmpty()
        if (issuerX5c.isNotEmpty() && issuerHeader.containsKey("kid")) {
            return holderBindingFailure("SD-JWT issuer JWT x5c cannot be combined with kid")
        }
        if (issuerX5c.isNotEmpty()) {
            if (configuredSource?.identifier?.method != IdentifierMethodDefaults.X5C) {
                return holderBindingFailure("SD-JWT issuer JWT x5c requires a configured X.509 issuer authentication source")
            }
            val configuredChain = (configuredSource?.identifier?.identifier as? List<*>)?.mapNotNull { it as? String }
            val presentedChain = issuerX5c.map { (it as JsonPrimitive).content }
            if (configuredChain == null || presentedChain != configuredChain) {
                return holderBindingFailure("SD-JWT issuer JWT x5c does not match the configured X.509 issuer chain")
            }
        }

        // A trust domain anchors the issuer as a plain DID. The issuer JWT's kid names the signing key:
        // it is made absolute against the iss DID first (a relative "#fragment" is qualified with it,
        // an absolute kid must be a DID URL of that same DID), and it must be one of the DID
        // document's assertionMethod verification methods, embedded or referenced.
        val trustedIssuerDid = configuredSource?.identifier as? ExternalIdentifierDidOpts
        val issuerIdentifier =
            if (trustedIssuerDid != null && !issuer.isNullOrBlank() && trustedIssuerDid.identifier == issuer) {
                val kid = (issuerHeader["kid"] as? JsonPrimitive)?.takeIf { it.isString }?.content?.takeIf(String::isNotBlank)
                    ?: return holderBindingFailure("SD-JWT issuer JWT from DID issuer '$issuer' must name its signing key in kid")
                val absoluteKid = absoluteDidUrl(issuer, kid)
                    ?: return holderBindingFailure("SD-JWT issuer JWT kid is not a verification method of the trusted issuer DID '$issuer'")
                val assertionMethods = assertionMethodIds(issuer)
                    ?: return holderBindingFailure("the trusted issuer DID '$issuer' could not be resolved")
                if (absoluteKid !in assertionMethods) {
                    return holderBindingFailure("SD-JWT issuer JWT kid '$absoluteKid' is not an assertionMethod of '$issuer'")
                }
                ExternalIdentifierDidOpts(identifier = absoluteKid)
            } else {
                configuredSource?.identifier
            }

        return verifySdJwtWithIssuerSource(
            presentation = presentation,
            issuerIdentifier = issuerIdentifier,
            trustedJwks = configuredSource?.trustedJwks,
            expectedNonce = expectedNonce,
            expectedAudience = expectedAudience,
            requireCryptographicHolderBinding = requireCryptographicHolderBinding,
        )
    }

    /**
     * Verifies a DID-issued SD-JWT VC through the OpenID Federation entity it names in `fed` (DIIP v5,
     * Appendix B): exactly one admitted `vc_issuer` key set of that entity, and a header `kid` that is a
     * DID URL of the `iss` DID and equals the `kid` of one of its keys. No DID document is consulted and
     * no header key material is accepted; anything else fails closed.
     */
    private suspend fun verifySdJwtWithFederationEntity(
        presentation: String,
        issuer: String,
        federated: FederatedCredentialIssuer.Applicable,
        expectedNonce: String,
        expectedAudience: String,
        requireCryptographicHolderBinding: Boolean,
    ): IdkResult<HolderBindingResult, IdkError> {
        if (federated.sources.size > 1) {
            return holderBindingFailure("multiple configured issuer authentication sources match federation entity '${federated.entity}'")
        }
        val header = sdJwtIssuerHeader(presentation)
            ?: return holderBindingFailure("SD-JWT issuer JWT protected header is malformed")
        val headerIssuerElement = header["iss"]
        if (headerIssuerElement != null && (headerIssuerElement as? JsonPrimitive)?.takeIf { it.isString }?.content != issuer) {
            return holderBindingFailure("SD-JWT issuer JWT protected-header iss must agree with the issuer claim")
        }
        listOf("jwk", "jku", "x5u", "x5c").firstOrNull(header::containsKey)?.let { member ->
            return holderBindingFailure("SD-JWT issuer JWT header '$member' cannot be used with OpenID Federation issuer keys")
        }
        val kid = (header["kid"] as? JsonPrimitive)?.takeIf { it.isString }?.content?.takeIf(String::isNotBlank)
            ?: return holderBindingFailure("SD-JWT issuer JWT from DID issuer '$issuer' must name its signing key in kid")
        if (!FederatedCredentialIssuer.isDidUrlOf(issuer, kid)) {
            return holderBindingFailure("SD-JWT issuer JWT kid '$kid' is not a DID URL of the issuer DID '$issuer'")
        }
        // The verifier selects the key by exact kid from the admitted vc_issuer JWK Set only.
        return verifySdJwtWithIssuerSource(
            presentation = presentation,
            issuerIdentifier = null,
            trustedJwks = federated.sources.single().trustedJwks,
            expectedNonce = expectedNonce,
            expectedAudience = expectedAudience,
            requireCryptographicHolderBinding = requireCryptographicHolderBinding,
        )
    }

    private suspend fun verifySdJwtWithIssuerSource(
        presentation: String,
        issuerIdentifier: com.sphereon.crypto.resolution.IdentifierOptsOrResult?,
        trustedJwks: JsonObject?,
        expectedNonce: String,
        expectedAudience: String,
        requireCryptographicHolderBinding: Boolean,
    ): IdkResult<HolderBindingResult, IdkError> {
        // Use the existing SD-JWT verification which handles full KB-JWT verification
        val verifyArgs =
            VerifySdJwtArgs(
                sdJwt = presentation,
                identifier = issuerIdentifier,
                trustedJwks = trustedJwks,
                expectedAudience = expectedAudience,
                expectedNonce = expectedNonce,
                validateDisclosures = true,
            )

        val verifyResult = verifySdJwtCommand.execute(verifyArgs)

        if (verifyResult.isErr) {
            return Ok(
                HolderBindingResult(
                    verified = false,
                    bindingMethod = "kb-jwt",
                    signatureValid = false,
                    nonceValid = false,
                    audienceValid = false,
                    sdHashValid = false,
                    errors = listOf("SD-JWT verification failed: ${verifyResult.error.message}"),
                ),
            )
        }

        val result = verifyResult.value
        val keyBindingPresent = result.sdJwt.keyBindingJwt != null

        // Extract holder key from cnf claim if present
        val holderKeyJson = extractHolderKeyFromSdJwt(result.sdJwt.payload.fullPayload)

        // Determine individual validation results from error messages
        val nonceError = result.errorMessages.any { it.contains("nonce", ignoreCase = true) }
        val audienceError = result.errorMessages.any { it.contains("aud", ignoreCase = true) }
        val sdHashError = result.errorMessages.any { it.contains("sd_hash", ignoreCase = true) }

        val errors = result.errorMessages.toMutableList()
        if (requireCryptographicHolderBinding && !keyBindingPresent) {
            errors += "Credential Query requires cryptographic holder binding, but the SD-JWT presentation has no Key Binding JWT"
        }

        return Ok(
            HolderBindingResult(
                // Issuer authenticity and disclosure integrity remain mandatory when the query
                // accepts a presentation without KB-JWT. An optional KB-JWT, when supplied, is
                // still verified and result.isValid fails closed if that proof is invalid.
                verified = result.isValid && (!requireCryptographicHolderBinding || keyBindingPresent),
                holderKey = holderKeyJson,
                bindingMethod = if (keyBindingPresent) "kb-jwt" else null,
                signatureValid = result.signatureValid,
                nonceValid = if (keyBindingPresent) !nonceError else !requireCryptographicHolderBinding,
                audienceValid = if (keyBindingPresent) !audienceError else !requireCryptographicHolderBinding,
                sdHashValid = if (keyBindingPresent) !sdHashError else null,
                errors = errors,
                // Surface trust vs. crypto split so the wire-level error message can
                // distinguish "issuer key never resolved" (relative-kid / did:web fetch
                // / trust anchor) from a real ECDSA/EdDSA mismatch.
                issuerTrustEstablished = result.issuerTrustEstablished,
                issuerCryptoVerified = result.issuerCryptoVerified,
            ),
        )
    }

    /** Extract the issuer from the signed SD-JWT issuer JWT for trust-source selection. */
    /** [didUrl] made absolute against [did]: "#fragment" is qualified, an absolute URL must belong to [did]. */
    private fun absoluteDidUrl(did: String, didUrl: String): String? =
        when {
            didUrl.startsWith("#") && didUrl.length > 1 -> did + didUrl
            didUrl.startsWith("$did#") && didUrl.length > did.length + 1 -> didUrl
            else -> null
        }

    /** The absolute ids of [did]'s assertionMethod verification methods, or null when it cannot be resolved. */
    private suspend fun assertionMethodIds(did: String): Set<String>? {
        val registry = didResolverRegistryProvider?.invoke() ?: return null
        val method = did.removePrefix("did:").substringBefore(':').takeIf { did.startsWith("did:") && it.isNotBlank() } ?: return null
        val resolver = registry.getResolver(method) ?: return null
        val document = resolver.resolve(did, DidResolutionOptions()).getOrNull()?.didDocument ?: return null
        if (document.id != did) return null
        return document.getVerificationMethodsForPurpose(VerificationPurpose.ASSERTION_METHOD)
            .mapNotNull { absoluteDidUrl(did, it.id) }
            .toSet()
    }

    private fun sdJwtIssuer(presentation: String): String? =
        runCatching {
            val payloadSegment = presentation.substringBefore('~').split('.').getOrNull(1) ?: return null
            val payload = json.parseToJsonElement(decodeBase64Url(payloadSegment)).jsonObject
            (payload["iss"] as? JsonPrimitive)?.takeIf { it.isString }?.content
        }.getOrNull()

    /** The issuer-signed payload as presented (plain claims only), used to select issuer material. */
    private fun sdJwtIssuerPayload(presentation: String): JsonObject? =
        runCatching {
            val payloadSegment = presentation.substringBefore('~').split('.').getOrNull(1) ?: return null
            json.parseToJsonElement(decodeBase64Url(payloadSegment)).jsonObject
        }.getOrNull()

    private fun sdJwtIssuerHeader(presentation: String): JsonObject? =
        runCatching {
            val headerSegment = presentation.substringBefore('~').split('.').firstOrNull() ?: return null
            json.parseToJsonElement(decodeBase64Url(headerSegment)).jsonObject
        }.getOrNull()

    /**
     * Extract holder's public key from cnf claim in SD-JWT payload.
     */
    private fun extractHolderKeyFromSdJwt(payload: JsonObject): String? {
        return try {
            val cnf = payload["cnf"]?.jsonObject ?: return null
            val jwk = cnf["jwk"]?.jsonObject ?: return null
            jwk.toString()
        } catch (e: Exception) {
            log.debug("Could not extract holder key from cnf claim: ${e.message}")
            null
        }
    }

    /**
     * Verify the holder binding for an mDoc presentation per ISO 18013-5 §9.3 and ISO 18013-7
     * §B.4.3 (the OID4VP profile of the mdoc handover).
     *
     * Steps:
     * 1. Decode the base64url presentation as a CBOR `DeviceResponse`.
     * 2. For each `Document`:
     *    - Run [MdocValidations.fromDocument] (cert chain, IssuerAuth COSE_Sign1, validity
     *      window, docType match, IssuerSignedItem digest match against MSO `valueDigests`).
     *    - Reconstruct the OID4VP `SessionTranscript` using the existing mdoc library:
     *      `OpenID4VPHandover` for direct-post, or `OpenID4VPDCAPIHandover` for DC API
     *      with the raw browser Origin, nonce, and encryption-key JWK thumbprint.
     *    - Verify the `DeviceAuth` COSE_Sign1 over that transcript using the device public
     *      key from the MSO.
     * 3. Aggregate per-document results — any critical=true failure marks the whole binding
     *    invalid.
     *
     * @param verifierEncryptionJwkThumbprint Raw 32-byte SHA-256 thumbprint (RFC 7638) of
     *   the verifier's encryption-key JWK. Required for `direct_post.jwt` / `dc_api.jwt`;
     *   null for plain `direct_post` / `dc_api`. The §B.2.6 handover MUSt match the
     *   response mode actually used.
     */
    private suspend fun verifyMdocHolderBinding(
        presentation: String,
        expectedNonce: String,
        clientId: String?,
        responseUri: String?,
        responseMode: String?,
        callerOrigin: String?,
        expectedMdocDocumentType: String?,
        verifierEncryptionJwkThumbprint: ByteArray?,
        expectedZkRequests: List<com.sphereon.mdoc.data.device.ZkRequest>,
        zkProofProviders: List<com.sphereon.mdoc.data.device.ZkProofProvider>,
        documentResponseDecryptionKey: com.sphereon.crypto.core.cose.CoseKey?,
        documentResponseEncryptionParameters: Map<UInt, com.sphereon.mdoc.data.device.EncryptionParameters>,
        documentResponseEncryptionProviders: List<com.sphereon.mdoc.data.device.DocumentResponseEncryptionProvider>,
        iso18013MdocGeneratedNonce: String?,
    ): IdkResult<HolderBindingResult, IdkError> {
        log.debug("Verifying mDoc holder binding")

        val dcApiResponseMode = responseMode?.takeIf { it == "dc_api" || it == "dc_api.jwt" }
        val digitalCredentialsApi = dcApiResponseMode != null
        if (clientId.isNullOrBlank()) {
            return Ok(
                HolderBindingResult(
                    verified = false,
                    bindingMethod = "mdoc-device-auth",
                    signatureValid = false,
                    nonceValid = false,
                    audienceValid = false,
                    sdHashValid = null,
                    errors =
                        listOf(
                            "mDoc holder-binding verification requires the OID4VP context (clientId).",
                        ),
                ),
            )
        }
        if (!digitalCredentialsApi && responseUri.isNullOrBlank()) {
            return Ok(mdocFailure("mDoc holder-binding verification requires the OID4VP context (responseUri)."))
        }

        // The presentation is base64url(CBOR(DeviceResponse)) — see ISO 18013-7 §B.3.
        val deviceResponseBytes =
            try {
                presentation.decodeFromBase64Url()
            } catch (expected: Exception) {
                return Ok(mdocFailure("Failed to base64url-decode the mDoc presentation: ${expected.message}"))
            }

        val deviceResponse =
            deviceResponseCborCodec
                .decode(deviceResponseBytes)
                .getOrElse { error ->
                    return Ok(mdocFailure("Failed to CBOR-decode DeviceResponse: ${error.message.defaultMessage}"))
                }.value

        val documents = deviceResponse.documents.orEmpty().toMutableList()
        val zkDocuments = deviceResponse.zkDocuments.orEmpty().toMutableList()
        val encryptedDocuments = deviceResponse.encryptedDocuments.orEmpty()
        if (documents.isEmpty() && zkDocuments.isEmpty() && encryptedDocuments.isEmpty()) {
            return Ok(mdocFailure("DeviceResponse contains no documents to verify."))
        }

        val expectedSessionTranscript =
            if (dcApiResponseMode != null) {
                val origin = callerOrigin
                if (origin.isNullOrBlank() || clientId != "origin:$origin") {
                    return Ok(mdocFailure("DC API mDoc verification requires the validated browser origin matching client_id."))
                }
                if (iso18013MdocGeneratedNonce != null) {
                    return Ok(mdocFailure("DC API mDoc verification cannot use the ISO Annex B mdoc-generated nonce."))
                }
                try {
                    Oid4vpDeviceAuthenticationContext(
                        responseMode = dcApiResponseMode,
                        clientId = clientId,
                        authorizationRequestNonce = expectedNonce,
                        responseUri = responseUri,
                        callerOrigin = origin,
                        verifierEncryptionJwkThumbprint = verifierEncryptionJwkThumbprint,
                        iso18013MdocGeneratedNonce = iso18013MdocGeneratedNonce,
                    ).toSessionTranscript()
                } catch (expected: IllegalArgumentException) {
                    return Ok(mdocFailure(expected.message ?: "Invalid DC API mDoc handover context."))
                } catch (expected: IllegalStateException) {
                    return Ok(mdocFailure(expected.message ?: "Invalid DC API mDoc handover context."))
                }
            } else if (iso18013MdocGeneratedNonce != null) {
                SessionTranscript.fromIso18013Oid4vp(
                    clientId = clientId,
                    responseUri = responseUri ?: return Ok(mdocFailure("Missing OID4VP responseUri.")),
                    mdocGeneratedNonce = iso18013MdocGeneratedNonce,
                    nonce = expectedNonce,
                )
            } else {
                SessionTranscript.fromOid4vpClientIdAndResponseUri(
                    clientId = clientId,
                    nonce = expectedNonce,
                    jwkThumbprint = verifierEncryptionJwkThumbprint,
                    responseUri = responseUri ?: return Ok(mdocFailure("Missing OID4VP responseUri.")),
                )
            }

        if (encryptedDocuments.isNotEmpty()) {
            val decryptionKey = documentResponseDecryptionKey
                ?: return Ok(
                    mdocFailure(
                        "DeviceResponse contains encryptedDocuments but this verifier session has no " +
                            "document-response decryption key.",
                    ),
                )
            if (documentResponseEncryptionParameters.isEmpty()) {
                return Ok(mdocFailure("Encrypted mDoc response parameters are not configured for this verifier session."))
            }
            if (documentResponseEncryptionProviders.isEmpty()) {
                return Ok(mdocFailure("No mDoc document-response decryption provider is configured."))
            }

            for (encrypted in encryptedDocuments) {
                val parameters = documentResponseEncryptionParameters[encrypted.docRequestID]
                    ?: return Ok(
                        mdocFailure(
                            "No document-response encryption parameters are configured for docRequestID=" +
                                encrypted.docRequestID,
                        ),
                    )
                val provider =
                    DocumentResponseEncryptionProviderResolver
                        .resolve(parameters, documentResponseEncryptionProviders)
                        .getOrElse { return Ok(mdocFailure(it.message.defaultMessage)) }
                val plaintext =
                    provider
                        .decrypt(
                            encrypted = encrypted,
                            recipientPrivateKey = decryptionKey,
                            sessionTranscript = expectedSessionTranscript,
                            parameters = parameters,
                        ).getOrElse { return Ok(mdocFailure(it.message.defaultMessage)) }
                val decryptedDocuments = plaintext.documents.orEmpty()
                val decryptedZkDocuments = plaintext.zkDocuments.orEmpty()
                if (decryptedDocuments.isEmpty() && decryptedZkDocuments.isEmpty()) {
                    return Ok(mdocFailure("Encrypted mDoc response envelope contained no documents."))
                }
                documents += decryptedDocuments
                zkDocuments += decryptedZkDocuments
            }
        }

        val expectedDocumentType =
            expectedMdocDocumentType?.takeIf { it.isNotBlank() }
                ?: return Ok(
                    mdocFailure(
                        "mDoc document type validation requires the verifier's persisted DCQL meta.doctype_value.",
                    ),
                )
        val mismatchedDocumentType =
            documents.asSequence().map { it.docType.toString() }
                .plus(zkDocuments.asSequence().map { it.documentData.docType.toString() })
                .firstOrNull { it != expectedDocumentType }
        if (mismatchedDocumentType != null) {
            return Ok(
                mdocFailure(
                    "mDoc document type mismatch: expected '$expectedDocumentType', got '$mismatchedDocumentType'",
                ),
            )
        }

        val errors = mutableListOf<String>()
        var allDocsVerified = true
        var allDeviceAuthsValid = true
        var allZkProofsValid = true

        // Certificate trust is intentionally evaluated later by the shared OID4VP
        // credential-trust validator, consistently with SD-JWT and W3C credentials. Empty
        // effective trust domains reject every issuer by default (fail-closed); issuer-auth and
        // device-auth signatures still have to verify.

        // Track issuer-auth signature failures separately from document content/validity failures.
        var anyIssuerAuthSignatureFailed = false

        documents.forEach { document ->
            val mdocResults =
                mdocValidations.withParams(
                    issuerAuth = null,
                    document = document,
                    mdocVerificationTypes = OID4VP_MDOC_HOLDER_BINDING_VALIDATIONS,
                    trustedCerts = null,
                    verificationTime = null,
                    keyInfo = null,
                    allowNotYetValidDocuments = false,
                    allowExpiredDocuments = false,
                )
            // Only the COSE issuer-auth failure contributes to signatureValid. Content or
            // validity failures still reject the document, and trust-domain results are handled later.
            val docTypeStr = document.docType.toString()
            mdocResults.verifications.forEach { v ->
                if (v.error && v.critical) {
                    val detail = "$docTypeStr: ${v.message ?: v.name}"
                    errors += detail
                    allDocsVerified = false
                    when (v.name) {
                        com.sphereon.crypto.core.CryptoConst.COSE_LITERAL -> anyIssuerAuthSignatureFailed = true
                    }
                }
            }

            val deviceAuthResult =
                deviceAuthValidation.verifyDeviceAuth(
                    document = document,
                    expectedSessionTranscript = expectedSessionTranscript,
                )
            if (deviceAuthResult.error && deviceAuthResult.critical) {
                allDocsVerified = false
                allDeviceAuthsValid = false
                errors += "$docTypeStr: ${deviceAuthResult.message ?: deviceAuthResult.name}"
            }
        }

        // A ZkDocument has no IssuerSigned/DeviceSigned structure on which the normal mdoc
        // digest and DeviceAuth checks can operate. It must instead be matched to the request
        // that authorized its system identifier and verified by an explicitly configured backend.
        zkDocuments.forEach { zkDocument ->
            val systemId = zkDocument.documentData.zkSystemId
            val expectedRequest =
                expectedZkRequests.firstOrNull { request ->
                    request.systemSpecs.any { spec -> spec.zkSystemId == systemId }
                }
            if (expectedRequest == null) {
                allZkProofsValid = false
                allDocsVerified = false
                errors += "${zkDocument.documentData.docType}: ZKP system '$systemId' was not requested"
                return@forEach
            }

            val providerResult = ZkProofProviderResolver.resolve(expectedRequest, zkProofProviders)
            if (providerResult.isErr) {
                allZkProofsValid = false
                allDocsVerified = false
                errors += "${zkDocument.documentData.docType}: ${providerResult.error.message.defaultMessage}"
                return@forEach
            }
            val provider = providerResult.value
            if (provider == null) {
                allZkProofsValid = false
                allDocsVerified = false
                errors += "${zkDocument.documentData.docType}: no compatible ZKP verifier is configured"
                return@forEach
            }

            val verification = provider.verifyProof(expectedRequest, zkDocument, expectedSessionTranscript)
            if (verification.isErr) {
                allZkProofsValid = false
                allDocsVerified = false
                errors += "${zkDocument.documentData.docType}: ${verification.error.message.defaultMessage}"
            } else if (!verification.value) {
                allZkProofsValid = false
                allDocsVerified = false
                errors += "${zkDocument.documentData.docType}: ZKP verification failed"
            }
        }

        // Cryptographic-signature outcome bucket: TRUE iff every issuer-auth signature AND every
        // device-auth signature actually verified.
        val allSigsValid = !anyIssuerAuthSignatureFailed && allDeviceAuthsValid && allZkProofsValid
        return Ok(
            HolderBindingResult(
                verified = allDocsVerified,
                bindingMethod = "mdoc-device-auth",
                signatureValid = allSigsValid,
                // OID4VP §10 / §B.2.6: the holder's nonce binding lives inside the session
                // transcript (the verifier's nonce is mixed into the OpenID4VPHandover). If the
                // device-auth signature verifies, the holder used the same transcript bytes
                // — including the same nonce — that we reconstructed.
                nonceValid = allDeviceAuthsValid && allZkProofsValid,
                audienceValid = allDeviceAuthsValid && allZkProofsValid,
                sdHashValid = null, // Not applicable for mDoc
                errors = errors,
            ),
        )
    }

    private fun mdocFailure(message: String): HolderBindingResult =
        HolderBindingResult(
            verified = false,
            bindingMethod = "mdoc-device-auth",
            signatureValid = false,
            nonceValid = false,
            audienceValid = false,
            sdHashValid = null,
            errors = listOf(message),
        )

    /**
     * Verify holder binding in JWT VP using proof signature.
     *
     * JWT VP (Verifiable Presentation) contains:
     * - Header with holder's key reference (kid; an x5c chain is accepted only with exact configured X.509 trust)
     * - Payload with nonce and aud claims
     * - Signature from holder's private key
     *
     * Verification steps:
     * 1. Parse JWT and extract header/payload
     * 2. Verify the signature using verifier-admitted identifier or key-set resolution
     * 3. Validate nonce claim matches expected value
     * 4. Validate aud claim matches expected value
     * 5. Validate timing claims (iat, exp) if present
     */
    private suspend fun verifyJwtVpHolderBinding(
        presentation: String,
        expectedNonce: String,
        expectedAudience: String,
        trustedAuthentications: List<TrustedAuthenticationResolution>,
        classification: com.sphereon.openid.oid4vc.common.vcdm.VcdmClassification,
    ): IdkResult<HolderBindingResult, IdkError> {
        log.debug("Verifying JWT VP holder binding")

        val errors = mutableListOf<String>()

        // Parse JWT
        val jwtParts = presentation.split(".")
        if (jwtParts.size != JWT_PART_COUNT) {
            return Ok(
                HolderBindingResult(
                    verified = false,
                    bindingMethod = BINDING_METHOD_JWT_PROOF,
                    signatureValid = false,
                    nonceValid = false,
                    audienceValid = false,
                    errors = listOf("Invalid JWT format: expected 3 parts, got ${jwtParts.size}"),
                ),
            )
        }

        // Decode payload to validate claims
        val payloadJson =
            try {
                val payloadDecoded = decodeBase64Url(jwtParts[1])
                json.parseToJsonElement(payloadDecoded).jsonObject
            } catch (e: Exception) {
                return Ok(
                    HolderBindingResult(
                        verified = false,
                        bindingMethod = BINDING_METHOD_JWT_PROOF,
                        signatureValid = false,
                        nonceValid = false,
                        audienceValid = false,
                        errors = listOf("Failed to decode JWT payload: ${e.message}"),
                    ),
                )
            }

        val holder = vcdmHolderController(classification)
            ?: return holderBindingFailure("VCDM VP holder/controller is required for compact holder binding")
        val matchingSources = trustedAuthentications.filter {
            it.purpose == TrustedAuthenticationPurpose.HOLDER && it.controller == holder
        }
        if (matchingSources.size > 1) {
            return holderBindingFailure("multiple configured holder authentication sources match controller '$holder'")
        }
        val configuredSource = matchingSources.singleOrNull()
        val holderIsDid = holder.startsWith("did:")
        if (!holderIsDid && configuredSource == null) {
            return holderBindingFailure("non-DID VCDM VP holder '$holder' requires an exact configured authentication source")
        }

        val headerJson = try {
            json.parseToJsonElement(decodeBase64Url(jwtParts[0])).jsonObject
        } catch (e: Exception) {
            return holderBindingFailure("Failed to decode JWT protected header: ${e.message}")
        }
        val typ = (headerJson["typ"] as? JsonPrimitive)?.takeIf { it.isString }?.content
        val cty = (headerJson["cty"] as? JsonPrimitive)?.takeIf { it.isString }?.content
        if (headerJson.containsKey("typ") && typ.isNullOrBlank()) {
            return holderBindingFailure("JWT protected header 'typ' must be a non-empty string")
        }
        if (headerJson.containsKey("cty") && cty.isNullOrBlank()) {
            return holderBindingFailure("JWT protected header 'cty' must be a non-empty string")
        }
        if (classification.document.version == VcdmVersion.V1_1 && typ != null && !typ.equals("JWT", ignoreCase = true)) {
            return holderBindingFailure("VCDM 1.1 JWT VP typ must be JWT when present")
        }
        if (classification.document.version == VcdmVersion.V2_0 &&
            typ != null &&
            typ !in setOf("vp+jwt", "application/vp+jwt")
        ) {
            return holderBindingFailure("VCDM 2.0 JWT VP typ must be vp+jwt or application/vp+jwt when present")
        }
        if (classification.document.version == VcdmVersion.V2_0 && cty !in setOf(null, "vp", "application/vp")) {
            return holderBindingFailure("VCDM 2.0 JWT VP cty must identify a verifiable presentation")
        }
        // `iss` is a registered JWT payload claim, but a non-standard protected-header copy
        // must never be allowed to identify a different holder.  Keep both envelopes bound to
        // the classified VCDM holder before any key resolution is attempted.
        val payloadIssuer = payloadJson["iss"]
        if (payloadIssuer != null) {
            val issuer = (payloadIssuer as? JsonPrimitive)?.takeIf { it.isString }?.content
            if (issuer.isNullOrBlank() || issuer != holder) {
                return holderBindingFailure("JWT payload iss must agree with the VCDM VP holder")
            }
        }
        val headerIssuer = headerJson["iss"]
        if (headerIssuer != null) {
            val issuer = (headerIssuer as? JsonPrimitive)?.takeIf { it.isString }?.content
            if (issuer.isNullOrBlank() || issuer != holder) {
                return holderBindingFailure("JWT protected-header iss must agree with the VCDM VP holder")
            }
        }
        val forbiddenEmbeddedKeyClaims = listOf("jwk", "jku", "x5u")
        val embeddedForbiddenClaim = forbiddenEmbeddedKeyClaims.firstOrNull(headerJson::containsKey)
        if (embeddedForbiddenClaim != null) {
            return holderBindingFailure("JWT header '$embeddedForbiddenClaim' cannot be used as a holder trust anchor")
        }
        val x5cElement = headerJson["x5c"]
        if (x5cElement != null &&
            (x5cElement !is JsonArray || x5cElement.any { it !is JsonPrimitive || !it.isString || it.content.isBlank() })
        ) {
            return holderBindingFailure("JWT header 'x5c' must be a non-empty array of certificate strings")
        }
        val x5c = (x5cElement as? JsonArray).orEmpty()
        if (x5c.isNotEmpty() &&
            (configuredSource == null || configuredSource.identifier?.method != IdentifierMethodDefaults.X5C)
        ) {
            return holderBindingFailure("JWT header 'x5c' requires a configured X.509 holder authentication source")
        }
        if (x5c.isNotEmpty()) {
            val presentedChain = x5c.map { (it as JsonPrimitive).content }
            val configuredChain = (configuredSource?.identifier?.identifier as? List<*>)?.mapNotNull { it as? String }
            if (configuredChain == null || presentedChain != configuredChain) {
                return holderBindingFailure("JWT header 'x5c' does not match the configured X.509 holder chain")
            }
        }
        val kid = (headerJson["kid"] as? JsonPrimitive)?.takeIf { it.isString }?.content
        if (headerJson.containsKey("kid") && kid.isNullOrBlank()) {
            return holderBindingFailure("JWT header 'kid' must be a non-empty string")
        }
        if (x5c.isNotEmpty() && kid != null) {
            return holderBindingFailure("JWT header 'x5c' cannot be combined with kid")
        }
        if (holderIsDid && kid != null && !kid.startsWith("$holder#")) {
            return holderBindingFailure("DID holder JWT 'kid' must be an absolute DID URL for the VP holder")
        }

        // Validate nonce claim
        val nonceValid = validateNonceClaim(payloadJson, expectedNonce, errors)

        // Validate audience claim
        val audienceValid = validateAudienceClaim(payloadJson, expectedAudience, errors)

        // Validate JWT NumericDate claims before accepting holder binding. These claims are
        // security-relevant replay/freshness constraints, not merely informational metadata.
        val temporalClaimsValid = validateTemporalClaims(payloadJson, errors)

        // Verify signature using JWS verification command
        val jws = JwsCompact(presentation)
        val verifyArgs = VerifyJwsArgs(
            jws = jws,
            identifier = configuredSource?.identifier,
            trustedJwks = configuredSource?.trustedJwks,
        )

        val verifyResult = verifyJwsCommand.execute(verifyArgs)

        val signatureValid =
            if (verifyResult.isErr) {
                errors.add("JWT signature verification failed: ${verifyResult.error.message}")
                false
            } else {
                if (!verifyResult.value.isValid || verifyResult.value.cryptoVerified != true) {
                    errors.add("JWT signature is invalid or cryptographic verification was not established")
                }
                verifyResult.value.isValid && verifyResult.value.cryptoVerified == true && verifyResult.value.trustEstablished
            }

        val verified = signatureValid && nonceValid && audienceValid && temporalClaimsValid

        return Ok(
            HolderBindingResult(
                verified = verified,
                // Embedded key material is never an authenticated holder key. The exact
                // configured/canonical source above remains the source of truth.
                holderKey = null,
                bindingMethod = BINDING_METHOD_JWT_PROOF,
                signatureValid = signatureValid,
                nonceValid = nonceValid,
                audienceValid = audienceValid,
                sdHashValid = null, // Not applicable for JWT VP
                errors = errors,
            ),
        )
    }

    private fun vcdmHolderController(
        classification: com.sphereon.openid.oid4vc.common.vcdm.VcdmClassification,
    ): String? {
        // VCDM 2.0 makes `holder` optional and permits holder information to come from the
        // securing mechanism. For a compact JWT VP, the signed `iss` claim identifies that
        // controller. It is only used to select an already admitted authentication source (or
        // the existing DID-resolution path); acceptance still requires trusted cryptographic
        // verification plus the nonce/audience checks below.
        val element = classification.document.json["holder"]
            ?: classification.rawPayload["iss"]
        return when (element) {
            is JsonPrimitive -> element.takeIf { it.isString }?.content?.takeIf { it.isNotBlank() }
            is JsonObject -> (element["id"] as? JsonPrimitive)?.takeIf { it.isString }?.content?.takeIf { it.isNotBlank() }
            else -> null
        }
    }

    private fun holderBindingFailure(message: String): IdkResult<HolderBindingResult, IdkError> =
        Ok(
            HolderBindingResult(
                verified = false,
                bindingMethod = BINDING_METHOD_JWT_PROOF,
                signatureValid = false,
                nonceValid = false,
                audienceValid = false,
                errors = listOf(message),
            ),
        )

    /**
     * Validate nonce claim in JWT payload.
     */
    private fun validateNonceClaim(
        payload: JsonObject,
        expectedNonce: String,
        errors: MutableList<String>,
    ): Boolean {
        val nonceElement = payload["nonce"]
        val nonce = (nonceElement as? JsonPrimitive)?.takeIf { it.isString }?.content
        return when {
            nonceElement == null -> {
                errors.add("JWT missing required 'nonce' claim")
                false
            }

            nonce == null -> {
                errors.add("JWT 'nonce' claim must be a JSON string")
                false
            }

            nonce != expectedNonce -> {
                errors.add("JWT 'nonce' claim mismatch: expected '$expectedNonce' but got '$nonce'")
                false
            }

            else -> {
                true
            }
        }
    }

    /**
     * Validate audience claim in JWT payload.
     * The aud claim can be a single string or an array of strings.
     */
    private fun validateAudienceClaim(
        payload: JsonObject,
        expectedAudience: String,
        errors: MutableList<String>,
    ): Boolean {
        val audElement = payload["aud"]
        if (audElement == null) {
            errors.add("JWT missing required 'aud' claim")
            return false
        }

        val audiences =
            when (audElement) {
                is JsonPrimitive -> {
                    if (!audElement.isString) {
                        errors.add("JWT 'aud' claim must be a JSON string or non-empty array of strings")
                        return false
                    }
                    listOf(audElement.content)
                }

                is JsonArray -> {
                    if (audElement.isEmpty() || audElement.any { it !is JsonPrimitive || !(it as JsonPrimitive).isString }) {
                        errors.add("JWT 'aud' claim must be a JSON string or non-empty array of strings")
                        return false
                    }
                    audElement.map { (it as JsonPrimitive).content }
                }

                else -> {
                    errors.add("JWT 'aud' claim must be a JSON string or non-empty array of strings")
                    return false
                }
            }

        if (audiences.any { it.isBlank() }) {
            errors.add("JWT 'aud' claim must not contain blank audience values")
            return false
        }
        if (audiences.size != audiences.toSet().size) {
            errors.add("JWT 'aud' claim must contain unique audience values")
            return false
        }

        return if (expectedAudience in audiences) {
            true
        } else {
            errors.add("JWT 'aud' claim mismatch: expected '$expectedAudience' but got $audiences")
            false
        }
    }

    private fun validateTemporalClaims(
        payload: JsonObject,
        errors: MutableList<String>,
    ): Boolean {
        fun numericDate(name: String): Double? {
            val element = payload[name] ?: return null
            val primitive = element as? JsonPrimitive
            if (primitive == null || primitive.isString || primitive.doubleOrNull?.isFinite() != true) {
                errors.add("JWT '$name' claim must be a finite JSON number")
                return null
            }
            return primitive.doubleOrNull
        }

        val iat = numericDate("iat")
        val nbf = numericDate("nbf")
        val exp = numericDate("exp")
        val malformed =
            (payload.containsKey("iat") && iat == null) ||
                (payload.containsKey("nbf") && nbf == null) ||
                (payload.containsKey("exp") && exp == null)
        if (malformed) return false

        // RFC 7519 defines these claims independently. In particular, `iat` is the token
        // issuance time and MAY be later than `nbf` when an already-valid statement is signed.
        // Enforce each registered claim's own semantics below; do not invent an ordering rule.
        val now = Clock.System.now().epochSeconds.toDouble()
        if (iat != null && iat > now) {
            errors.add("JWT iat claim is in the future")
            return false
        }
        if (nbf != null && nbf > now) {
            errors.add("JWT nbf claim is in the future")
            return false
        }
        if (exp != null && exp < now) {
            errors.add("JWT exp claim is expired")
            return false
        }
        return true
    }

    /**
     * Decode base64url string to UTF-8 string.
     */
    private fun decodeBase64Url(input: String): String = input.decodeFromBase64Url().decodeToString()

    private companion object {
        private const val JWT_PART_COUNT = 3
        private const val BINDING_METHOD_JWT_PROOF = "jwt-proof"
    }
}

internal val OID4VP_MDOC_HOLDER_BINDING_VALIDATIONS =
    setOf(
        MdocVerification.ISSUER_AUTH_SIGNATURE,
        MdocVerification.DIGEST_VALUES,
        MdocVerification.DOC_TYPE,
        MdocVerification.VALIDITY,
    )
