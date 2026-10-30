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

@file:Suppress("TooGenericExceptionCaught")

package com.sphereon.crypto.jose.jws.command

import com.sphereon.core.api.Encoding
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.asOkResult
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.decodeFrom
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.service.TypedServiceCommandAdapter
import com.sphereon.crypto.core.KeyInfo
import com.sphereon.crypto.core.KeyType
import com.sphereon.crypto.core.ResolvedKeyInfo
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.crypto.core.jose.JwaAlgorithm
import com.sphereon.crypto.core.jose.Jwk
import com.sphereon.crypto.core.jose.generateJwkThumbprint
import com.sphereon.crypto.core.sign.SignatureService
import com.sphereon.crypto.jose.jws.JwsJsonGeneralWithIdentifiers
import com.sphereon.crypto.jose.jws.JwsJsonSignatureWithIdentifier
import com.sphereon.crypto.jose.jws.JwsUtils
import com.sphereon.crypto.jose.jws.JwsValidationResult
import com.sphereon.crypto.jose.jws.command.VerifyJwsArgs
import com.sphereon.crypto.jose.jws.command.VerifyJwsCommand
import com.sphereon.crypto.resolution.IdentifierOptsOrResult
import com.sphereon.crypto.resolution.IdentifierService
import com.sphereon.crypto.resolution.extern.ExternalIdentifierDidOpts
import com.sphereon.crypto.resolution.extern.ExternalIdentifierJwkOpts
import com.sphereon.crypto.resolution.extern.ExternalIdentifierResult
import com.sphereon.crypto.resolution.extern.ExternalIdentifierX5cOpts
import com.sphereon.crypto.resolution.managed.ManagedIdentifierKeyResult
import com.sphereon.crypto.resolution.managed.ManagedOptsKid
import com.sphereon.di.session.SessionContext
import com.sphereon.di.session.SessionScope
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import kotlinx.coroutines.CancellationException
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.experimental.ExperimentalObjCName
import kotlin.native.ObjCName
import kotlin.time.Clock

import dev.zacsweers.metro.ExposeImplBinding
/**
 * Command implementation for verifying JWS signatures
 */
@Inject
@SingleIn(SessionScope::class)
@OptIn(ExperimentalObjCName::class)
@ObjCName("VerifyJwsCommandImpl", exact = true)
@ExposeImplBinding
class VerifyJwsCommandImpl(
    execution: SessionExecution,
    private val identifierService: IdentifierService,
    private val signatureService: SignatureService,
) : TypedServiceCommandAdapter<VerifyJwsArgs, JwsValidationResult, IdkError>(
        commandId = VerifyJwsCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<VerifyJwsArgs>(),
        outputTypeToken = typeToken<JwsValidationResult>(),
    ),
    VerifyJwsCommand {
    override val commandId: String get() = VerifyJwsCommand.COMMAND_ID

    override suspend fun doExecute(
        args: VerifyJwsArgs,
        applyDuring: (VerifyJwsArgs) -> VerifyJwsArgs,
    ): IdkResult<JwsValidationResult, IdkError> {
        val appliedArgs = applyDuring(args)

        // Validate required fields
        val jws = appliedArgs.jws ?: run {
            log.warn("JWS_VERIFICATION_FAILED stage=input reason=jws_missing")
            return IdkResult.err(IdkError.fromString("JWS is required"))
        }

        // Convert to general format
        val general =
            try {
                JwsUtils.toGeneral(jws)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (expected: Exception) {
                log.warn("JWS_VERIFICATION_FAILED stage=serialization reason=jws_format_invalid causeType=${expected::class.simpleName}")
                return IdkResult.err(IdkError.fromString("Invalid JWS format: ${expected.message}", exception = expected))
            }

        // Verify each signature
        val errorMessages = mutableListOf<String>()
        val signaturesWithIdentifiers = mutableListOf<JwsJsonSignatureWithIdentifier>()
        val trustedJwks = appliedArgs.trustedJwks
        // Diagnostic flags split "couldn't establish trust in a key" from "key found but
        // crypto check failed". Aggregated across all signatures in this JWS.
        var anyResolutionFailed = false
        var anyCryptoAttempted = false
        var anyCryptoFailed = false

        for ((index, signature) in general.signatures.withIndex()) {
            var stage = "protected-header"
            try {
                // Decode protected header
                val protectedHeader = JwsUtils.decodeBase64UrlToJson(signature.protected)

                // Extract algorithm from header (used for multiple checks below)
                val algValue = protectedHeader["alg"]?.jsonPrimitive?.content

                // SECURITY: Reject "none" algorithm (RFC 9901 §8.1, RFC 8725 §2.1)
                if (algValue?.lowercase() == "none") {
                    log.warn("JWS_VERIFICATION_FAILED stage=protected-header reason=algorithm_none signatureIndex=$index")
                    errorMessages.add("Signature $index: Algorithm 'none' is not allowed for security reasons")
                    // No crypto attempt — pre-crypto rejection counts as trust-not-established.
                    anyResolutionFailed = true
                    continue
                }

                // Branch: when the caller pinned a trusted JWKS, signature verification MUST use
                // ONLY a key from that document. Identifier resolvers are not consulted.
                //
                // Embedded `jwk` / `x5c` headers are NOT refused: a caller that pins `trustedJwks`
                // is asserting the canonical trusted key set (typically resolved from a
                // pre-validated x5c chain or a published JWKS). Any embedded JOSE key material in
                // the header is informational. The signature check below is what makes the trust
                // decision binding: if the JWS was actually signed by a key not in `trustedJwks`,
                // signature verification fails and the result is rejected. The `kid` / alg-fitness
                // lookup against `trustedJwks` happens unchanged.
                if (trustedJwks != null) {
                    if (algValue == null) {
                        log.warn("JWS_VERIFICATION_FAILED stage=protected-header reason=algorithm_missing signatureIndex=$index")
                        errorMessages.add("Signature $index: Missing 'alg' in JWS header")
                        anyResolutionFailed = true
                        signaturesWithIdentifiers.add(
                            JwsJsonSignatureWithIdentifier(
                                protected = signature.protected,
                                parsedProtectedHeader = protectedHeader,
                                header = signature.header,
                                signature = signature.signature,
                                identifier = null,
                            ),
                        )
                        continue
                    }
                    val headerKid = protectedHeader["kid"]?.jsonPrimitive?.content
                    stage = "trusted-key-selection"
                    val selected = selectJwk(trustedJwks, headerKid, algValue)
                    if (selected == null) {
                        log.warn("JWS_VERIFICATION_FAILED stage=trusted-key-selection reason=trusted_key_missing signatureIndex=$index")
                        errorMessages.add(
                            "Signature $index: No matching trusted JWK for kid=$headerKid alg=$algValue",
                        )
                        // Trust establishment failure: pinned JWKS did not contain a usable key.
                        anyResolutionFailed = true
                        signaturesWithIdentifiers.add(
                            JwsJsonSignatureWithIdentifier(
                                protected = signature.protected,
                                parsedProtectedHeader = protectedHeader,
                                header = signature.header,
                                signature = signature.signature,
                                identifier = null,
                            ),
                        )
                        continue
                    }

                    val keyInfo = buildKeyInfoFromJwk(selected.jsonObject, algValue)
                    val signingInput = JwsUtils.createSigningInput(signature.protected, general.payload)
                    val signatureBytes = signature.signature.decodeFrom(Encoding.BASE64URL)

                    log.debug("Verifying signature against trusted JWKS")
                    stage = "cryptographic-verification"
                    anyCryptoAttempted = true
                    val isValid =
                        try {
                            verifyResolvedPublicJwkSignature(
                                keyInfo = keyInfo,
                                headerAlg = algValue,
                                input = signingInput,
                                signature = signatureBytes,
                            )
                        } catch (cancelled: CancellationException) {
                            throw cancelled
                        } catch (expected: Exception) {
                            log.warn("JWS_VERIFICATION_FAILED stage=cryptographic-verification reason=provider_exception signatureIndex=$index causeType=${expected::class.simpleName}")
                            errorMessages.add("Signature $index: Verification failed - ${expected.message}")
                            false
                        }

                    if (!isValid) {
                        log.warn("JWS_VERIFICATION_FAILED stage=cryptographic-verification reason=signature_invalid signatureIndex=$index")
                        errorMessages.add("Signature $index: Invalid signature")
                        anyCryptoFailed = true
                    }

                    signaturesWithIdentifiers.add(
                        JwsJsonSignatureWithIdentifier(
                            protected = signature.protected,
                            parsedProtectedHeader = protectedHeader,
                            header = signature.header,
                            signature = signature.signature,
                            identifier = null,
                        ),
                    )
                    continue
                }

                // Resolve identifier from header or use provided identifier
                stage = "identifier-resolution"
                val identifierResult =
                    if (appliedArgs.identifier != null) {
                        // Use provided identifier
                        identifierService.resolve(appliedArgs.identifier as IdentifierOptsOrResult)
                    } else {
                        // Resolve from header
                        resolveIdentifierFromHeader(protectedHeader)
                    }

                if (identifierResult.isErr) {
                    log.warn("JWS_VERIFICATION_FAILED stage=identifier-resolution reason=identifier_resolution_failed signatureIndex=$index providerCode=${identifierResult.error.code}")
                    errorMessages.add("Signature $index: Failed to resolve identifier - ${identifierResult.error.message.defaultMessage}")
                    // Trust establishment failure: no key resolved for this signature.
                    anyResolutionFailed = true
                    continue
                }

                stage = "key-admission"
                val identifierOptsOrResult = identifierResult.value

                // X.509 key extraction is not trust establishment. A verifier-admitted x5c
                // source must have performed enabled, successful chain validation; in particular
                // a disabled result (which intentionally reports error=false for extraction)
                // must never reach signature verification as trusted material.
                if (identifierOptsOrResult is ExternalIdentifierResult.X5c) {
                    val verification = identifierOptsOrResult.verificationResult
                    val validationSucceeded =
                        identifierOptsOrResult.identifierOpts.verify != false &&
                            !verification.error &&
                            !verification.critical &&
                            verification.message != "X509 verification has been disabled" &&
                            verification.publicKey != null
                    if (!validationSucceeded) {
                        log.warn("JWS_VERIFICATION_FAILED stage=key-admission reason=x509_trust_refused signatureIndex=$index")
                        errorMessages.add("Signature $index: X.509 chain validation was not successfully established")
                        anyResolutionFailed = true
                        continue
                    }
                }

                if (identifierOptsOrResult is ExternalIdentifierResult.Did &&
                    identifierOptsOrResult.didResolutionResult.didDocumentMetadata?.get("deactivated").toString().equals("true", ignoreCase = true)
                ) {
                    log.warn("JWS_VERIFICATION_FAILED stage=key-admission reason=did_deactivated signatureIndex=$index")
                    errorMessages.add("Signature $index: DID is deactivated")
                    anyResolutionFailed = true
                    continue
                }

                // Extract keyInfo from either managed or external result
                var keyInfo =
                    when (identifierOptsOrResult) {
                        is ManagedIdentifierKeyResult -> {
                            identifierOptsOrResult.keyInfo
                        }

                        is ExternalIdentifierResult -> {
                            identifierOptsOrResult.keyInfo
                        }

                        else -> {
                            log.warn("JWS_VERIFICATION_FAILED stage=key-admission reason=identifier_type_unsupported signatureIndex=$index")
                            errorMessages.add("Signature $index: Unsupported identifier result type")
                            anyResolutionFailed = true
                            continue
                        }
                    }

                // The identifier/provider choice does not override the protected-header
                // algorithm.  Enforce the resolved key's family, curve, use/key_ops and any
                // explicit algorithm constraint before both provider-backed and local crypto.
                keyInfo.jwsAlgorithmCompatibilityFailure(algValue)?.let { failure ->
                    log.warn("JWS_VERIFICATION_FAILED stage=key-admission reason=algorithm_key_incompatible signatureIndex=$index")
                    errorMessages.add("Signature $index: $failure")
                    anyCryptoFailed = true
                    signaturesWithIdentifiers.add(
                        JwsJsonSignatureWithIdentifier(
                            protected = signature.protected,
                            parsedProtectedHeader = protectedHeader,
                            header = signature.header,
                            signature = signature.signature,
                            identifier = identifierOptsOrResult,
                        ),
                    )
                    continue
                }

                // Create signing input
                val signingInput = JwsUtils.createSigningInput(signature.protected, general.payload)

                // Decode signature
                val signatureBytes = signature.signature.decodeFrom(Encoding.BASE64URL)

                // Validated X.509 and JWKS URL results carry resolved public keys. After the
                // trust and compatibility gates above, verify with the protected algorithm;
                // an unconstrained RSA certificate does not choose a JOSE padding or digest.
                log.debug("Verifying signature with keyInfo.signatureAlgorithm = ${keyInfo.signatureAlgorithm}")
                stage = "cryptographic-verification"
                anyCryptoAttempted = true
                val isValid =
                    try {
                        if (identifierOptsOrResult is ExternalIdentifierResult.JwksUrl || identifierOptsOrResult is ExternalIdentifierResult.X5c) {
                            verifyResolvedPublicJwkSignature(
                                keyInfo = keyInfo,
                                headerAlg = algValue,
                                input = signingInput,
                                signature = signatureBytes,
                            )
                        } else {
                            signatureService.isValidRawSignature(
                                keyInfo = keyInfo,
                                input = signingInput,
                                signature = signatureBytes,
                            )
                        }
                    } catch (cancelled: CancellationException) {
                        throw cancelled
                    } catch (expected: Exception) {
                        log.warn("JWS_VERIFICATION_FAILED stage=cryptographic-verification reason=provider_exception signatureIndex=$index causeType=${expected::class.simpleName}")
                        errorMessages.add("Signature $index: Verification failed - ${expected.message}")
                        false
                    }

                if (!isValid) {
                    val publicJwk = keyInfo.key as? Jwk
                    val keyType = publicJwk?.kty?.value ?: "unavailable"
                    val keyAlgorithm = keyInfo.signatureAlgorithm?.let { it::class.simpleName } ?: "unavailable"
                    val publicThumbprint = publicJwk?.let { runCatching { generateJwkThumbprint(it) }.getOrNull() } ?: "unavailable"
                    log.warn(
                        "JWS_VERIFICATION_FAILED stage=cryptographic-verification reason=signature_invalid " +
                            "signatureIndex=$index keyType=$keyType keyAlgorithm=$keyAlgorithm publicThumbprint=$publicThumbprint",
                    )
                    errorMessages.add("Signature $index: Invalid signature")
                    anyCryptoFailed = true
                }

                signaturesWithIdentifiers.add(
                    JwsJsonSignatureWithIdentifier(
                        protected = signature.protected,
                        parsedProtectedHeader = protectedHeader,
                        header = signature.header,
                        signature = signature.signature,
                        identifier = identifierOptsOrResult,
                    ),
                )
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (expected: Exception) {
                log.warn("JWS_VERIFICATION_FAILED stage=$stage reason=unexpected_exception signatureIndex=$index causeType=${expected::class.simpleName}")
                errorMessages.add("Signature $index: Unexpected error - ${expected.message}")
            }
        }

        val parsedPayload =
            try {
                JwsUtils.decodeBase64UrlToJson(general.payload)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (expected: Exception) {
                log.warn("JWS_VERIFICATION_FAILED stage=payload-decode reason=payload_decode_failed causeType=${expected::class.simpleName}")
                JsonObject(emptyMap())
            }

        if (general.signatures.isEmpty()) {
            log.warn("JWS_VERIFICATION_FAILED stage=signature-set reason=signatures_missing")
        }
        val isValid = errorMessages.isEmpty()
        // Trust establishment is true iff *every* signature in the JWS got a verification
        // key. cryptoVerified is null when no signature ever made it past identifier
        // resolution (purely a trust failure); else it reflects the aggregate of attempted
        // crypto checks. This lets callers distinguish "couldn't tell" from "actively wrong".
        val trustEstablished = !anyResolutionFailed && general.signatures.isNotEmpty()
        val cryptoVerified: Boolean? =
            when {
                !anyCryptoAttempted -> null
                anyCryptoFailed -> false
                else -> true
            }
        val result =
            JwsValidationResult(
                jws =
                    JwsJsonGeneralWithIdentifiers(
                        payload = general.payload,
                        signatures = signaturesWithIdentifiers,
                    ),
                isValid = isValid,
                errorMessages = errorMessages,
                verificationTime = Clock.System.now().toEpochMilliseconds(),
                parsedPayload = parsedPayload,
                trustEstablished = trustEstablished,
                cryptoVerified = cryptoVerified,
            )

        return result.asOkResult()
    }

    private suspend fun resolveIdentifierFromHeader(protectedHeader: kotlinx.serialization.json.JsonObject): IdkResult<IdentifierOptsOrResult, IdkError> {
        // Priority: x5c > jwk in header > kid (DID or managed)

        // Check for x5c (X.509 certificate chain)
        val x5c =
            protectedHeader["x5c"]?.let { element ->
                if (element is kotlinx.serialization.json.JsonArray) {
                    element.map { it.jsonPrimitive.content }
                } else {
                    null
                }
            }

        if (x5c != null) {
            val opts =
                ExternalIdentifierX5cOpts(
                    identifier = x5c,
                    // A header-provided chain is an admitted verifier trust input, so chain
                    // validation must be enabled before its leaf key can be trusted.
                    verify = true,
                )
            val result = identifierService.resolve(opts)
            return if (result.isErr) {
                IdkResult.err(IdkError.fromDTO(result.error))
            } else {
                IdkResult.ok(result.value)
            }
        }

        // Check for jwk in header
        val jwkElement = protectedHeader["jwk"]
        if (jwkElement is kotlinx.serialization.json.JsonObject) {
            // Convert JsonObject to Jwk
            val jwk = Jwk.fromJsonObject(jwkElement)

            // Create ResolvedKeyInfo directly from the embedded JWK
            val keyInfo = ResolvedKeyInfo.fromKey(jwk)

            // Create an ExternalIdentifierResult.Jwk with the embedded key
            val opts = ExternalIdentifierJwkOpts(identifier = jwk)

            val result =
                ExternalIdentifierResult.Jwk(
                    identifierOpts = opts,
                    jwks = arrayOf(keyInfo),
                    keyInfo = keyInfo,
                    x5c = null,
                )

            return IdkResult.ok(result)
        }

        // Check for kid (could be DID or managed key)
        val kid = protectedHeader["kid"]?.jsonPrimitive?.content

        if (kid != null) {
            val opts: IdentifierOptsOrResult =
                if (kid.startsWith("did:")) {
                    ExternalIdentifierDidOpts(identifier = kid)
                } else {
                    // Managed key kid. The protected alg is evaluated only after resolution;
                    // it must never become an input to provider key selection.
                    ManagedOptsKid(identifier = kid, lookup = managedKidLookup(kid))
                }
            val result = identifierService.resolve(opts)
            return if (result.isErr) {
                IdkResult.err(IdkError.fromDTO(result.error))
            } else {
                IdkResult.ok(result.value)
            }
        }

        return IdkResult.err(
            IdkError.fromString("Could not resolve identifier from JWS header. No x5c, jwk, or kid found."),
        )
    }

    /**
     * Build a [ResolvedKeyInfo] directly from a trusted-JWKS entry, stamped with the
     * [SignatureAlgorithm] derived from the JWS header `alg` so the signature service knows
     * exactly which scheme to verify under.
     */
    @Suppress("UNCHECKED_CAST")
    private fun buildKeyInfoFromJwk(
        jwkObject: JsonObject,
        headerAlg: String,
    ): ResolvedKeyInfo<*> {
        val jwk = Jwk.fromJsonObject(jwkObject)
        val base = ResolvedKeyInfo.fromKey(jwk) as ResolvedKeyInfo<*>
        if (base.signatureAlgorithm != null) return base
        val signatureAlg =
            try {
                SignatureAlgorithm.fromJose(JwaAlgorithm.fromValue(headerAlg))
            } catch (_: Exception) {
                null
            }
        return if (signatureAlg != null) {
            (base as ResolvedKeyInfo<KeyType>).copy(signatureAlgorithm = signatureAlg)
        } else {
            base
        }
    }

}

/** Build the managed selector without copying any untrusted protected-header algorithm. */
internal fun managedKidLookup(kid: String): KeyInfo<KeyType> = KeyInfo(kid = kid)
