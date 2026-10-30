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

package com.sphereon.crypto.jose.jwe.command

import com.sphereon.core.api.Encoding
import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.asOkResult
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.decodeFrom
import com.sphereon.core.api.encodeTo
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.error.IdkErrorType
import com.sphereon.core.api.service.TypedServiceCommandAdapter
import com.sphereon.crypto.core.KeyInfo
import com.sphereon.crypto.core.KeyInfoType
import com.sphereon.crypto.core.KeyVisibility
import com.sphereon.crypto.core.jose.JwaKeyType
import com.sphereon.crypto.core.jose.Jwk
import com.sphereon.crypto.core.json.cryptoJsonSerializer
import com.sphereon.crypto.core.kms.ConcatKdf
import com.sphereon.crypto.core.kms.ContentEncryptionAlgorithm
import com.sphereon.crypto.core.kms.EcdhUtils
import com.sphereon.crypto.core.kms.KeyAgreementAlgorithm
import com.sphereon.crypto.core.kms.KeyManagerService
import com.sphereon.crypto.core.kms.KeyWrapAlgorithm
import com.sphereon.crypto.core.kms.command.EcdhDeriveArgs
import com.sphereon.crypto.core.kms.command.EcdhDeriveCommand
import com.sphereon.crypto.core.kms.command.EcdhDeriveMode
import kotlinx.coroutines.CancellationException
import com.sphereon.crypto.jose.jwe.DecryptJweArgs
import com.sphereon.crypto.jose.jwe.DecryptJweCommand
import com.sphereon.crypto.jose.jwe.JweCompact
import com.sphereon.crypto.jose.jwe.JweDecryptionResult
import com.sphereon.crypto.jose.jwe.JweHeader
import com.sphereon.crypto.jose.jwe.JweJsonFlattened
import com.sphereon.crypto.jose.jwe.JweJsonGeneral
import com.sphereon.crypto.resolution.managed.ManagedIdentifierOptsOrResult
import com.sphereon.crypto.resolution.managed.ManagedOptsKeyInfo
import com.sphereon.crypto.resolution.managed.MultiManagedIdentifierService
import com.sphereon.di.session.SessionContext
import com.sphereon.di.session.SessionScope
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import kotlinx.serialization.json.JsonObject
import kotlin.experimental.ExperimentalObjCName
import kotlin.native.ObjCName

import dev.zacsweers.metro.ExposeImplBinding
/**
 * Command implementation for decrypting JWE
 *
 * This command decrypts a JWE by:
 * 1. Parsing the JWE (compact or JSON format)
 * 2. Decrypting the CEK using the recipient's private key (unwrapKey)
 * 3. Decrypting the ciphertext using the CEK
 * 4. Verifying the authentication tag (for AEAD algorithms)
 * 5. Optionally decompressing the plaintext if compression was used
 * 6. Returning the plaintext and header
 *
 * Supports all JWE formats:
 * - Compact serialization: header.encryptedKey.iv.ciphertext.tag
 * - JSON flattened: Single recipient JSON format
 * - JSON general: Multi-recipient JSON format (decrypts using first matching key)
 *
 * Security considerations:
 * - Always verifies authentication tag before returning plaintext
 * - Handles timing attacks by performing constant-time comparisons
 * - Validates all required header parameters
 * - Checks for critical headers and rejects if not understood
 */
@Inject
@SingleIn(SessionScope::class)
@OptIn(ExperimentalObjCName::class)
@ObjCName("DecryptJweCommandImpl", exact = true)
@ExposeImplBinding
class DecryptJweCommandImpl(
    execution: SessionExecution,
    private val identifierService: MultiManagedIdentifierService,
    private val keyManagerService: KeyManagerService,
    private val ecdhDeriveCommand: EcdhDeriveCommand,
) : TypedServiceCommandAdapter<DecryptJweArgs, JweDecryptionResult, IdkError>(
        commandId = DecryptJweCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<DecryptJweArgs>(),
        outputTypeToken = typeToken<JweDecryptionResult>(),
    ),
    DecryptJweCommand {
    override val commandId: String get() = DecryptJweCommand.COMMAND_ID

    private fun logDecryptionRefusal(stage: String, error: IdkErrorType) {
        val code = error.code.takeIf { it.matches(Regex("[A-Za-z0-9_.:-]{1,160}")) } ?: "unavailable"
        log.warn("JWE decryption refused stage=$stage code=$code")
    }

    private fun decryptionFailure(stage: String, message: String): IdkError =
        IdkError.fromString(message).also { logDecryptionRefusal(stage, it) }

    override suspend fun doExecute(
        args: DecryptJweArgs,
        applyDuring: (DecryptJweArgs) -> DecryptJweArgs,
    ): IdkResult<JweDecryptionResult, IdkError> {
        val appliedArgs = applyDuring(args)

        // Validate required fields
        val jwe = appliedArgs.jwe ?: return IdkResult.err(IdkError.fromString("JWE is required"))
        val decryptor = appliedArgs.decryptor ?: return IdkResult.err(IdkError.fromString("Decryptor is required"))

        // Step 1: Extract JWE components based on format
        val (header, encryptedKey, iv, ciphertext, authTag) =
            when (jwe) {
                is JweCompact -> {
                    Tuple5(jwe.header, jwe.encryptedKey, jwe.iv, jwe.ciphertext, jwe.authTag)
                }

                is JweJsonFlattened -> {
                    val hdr =
                        jwe.getProtectedHeader() ?: jwe.getUnprotectedHeader()
                            ?: return IdkResult.err(IdkError.fromString("No header in JWE"))
                    val encKey = jwe.encrypted_key.decodeFrom(Encoding.BASE64URL)
                    val ivBytes = jwe.iv.decodeFrom(Encoding.BASE64URL)
                    val ctBytes = jwe.ciphertext.decodeFrom(Encoding.BASE64URL)
                    val tagBytes = jwe.tag.decodeFrom(Encoding.BASE64URL)
                    Tuple5(hdr, encKey, ivBytes, ctBytes, tagBytes)
                }

                is JweJsonGeneral -> {
                    // For general format, handle multi-recipient decryption separately
                    return decryptJweJsonGeneral(jwe, decryptor, appliedArgs)
                }

                else -> {
                    return IdkResult.err(IdkError.fromString("Unsupported JWE type"))
                }
            }

        // Step 2: Get algorithm strings and convert to typed enums
        val keyAlgStr = header.alg ?: return IdkResult.err(IdkError.fromString("alg header is required"))
        val encAlgStr = header.enc ?: return IdkResult.err(IdkError.fromString("enc header is required"))

        val encAlg =
            ContentEncryptionAlgorithm.fromIdentifier(encAlgStr)
                ?: return IdkResult.err(IdkError.fromString("Unsupported content encryption algorithm: $encAlgStr"))

        // Check if this is an ECDH-ES algorithm
        val keyAgreementAlg = KeyAgreementAlgorithm.fromIdentifier(keyAlgStr)
        val keyWrapAlg = KeyWrapAlgorithm.fromIdentifier(keyAlgStr)

        // Provider-backed agreement and unwrap use an opaque handle. Preserve its provider,
        // alias and kid through the guarded KMS operation, without exporting private material.
        // Direct encryption needs the actual CEK; caller-supplied keys and unbound references
        // continue through normal identifier resolution.
        val decryptorReference =
            (decryptor as? ManagedOptsKeyInfo)
                ?.takeIf { it.lookup == it.identifier }
                ?.identifier
                ?.takeIf {
                    (keyAgreementAlg != null || (keyWrapAlg != null && keyWrapAlg != KeyWrapAlgorithm.DIR)) &&
                        it.isProviderBackedReference()
                }
        val decryptorKeyInfo =
            decryptorReference ?: run {
                val identifierResult = identifierService.resolve(decryptor)
                if (!identifierResult.isOk) {
                    logDecryptionRefusal("identifier-resolution", identifierResult.error)
                    return IdkResult.err(IdkError.fromDTO(identifierResult.error))
                }
                identifierResult.value.asResult().keyInfo
            }

        // Step 3: Derive or unwrap the CEK
        val cek: ByteArray
        if (keyAgreementAlg != null) {
            // ECDH-ES algorithm - perform key agreement to derive CEK
            cek =
                performEcdhEsDecryption(
                    keyAgreementAlg = keyAgreementAlg,
                    encAlgStr = encAlgStr,
                    header = header,
                    encryptedKey = encryptedKey,
                    decryptorKeyInfo = decryptorKeyInfo,
                ).getOrElse { error -> return Err(error) }
        } else if (keyWrapAlg != null) {
            cek =
                if (keyWrapAlg == KeyWrapAlgorithm.DIR) {
                    // Direct encryption - the shared symmetric key IS the CEK
                    // Extract the symmetric key from the decryptor's KeyInfo
                    extractSymmetricKeyForDir(decryptorKeyInfo, encAlgStr)
                        .getOrElse { error -> return Err(error) }
                } else {
                    // Unwrap the CEK using our private key
                    try {
                        keyManagerService.unwrapKey(
                            unwrappingKeyInfo = decryptorKeyInfo,
                            wrappedKey = encryptedKey,
                            algorithm = keyWrapAlg,
                        )
                    } catch (expected: Throwable) {
                        if (expected is CancellationException) throw expected
                        return IdkResult.err(decryptionFailure("key-unwrap", "Key unwrapping failed"))
                    }
                }
        } else {
            return IdkResult.err(IdkError.fromString("Unsupported key encryption algorithm: $keyAlgStr"))
        }

        // Step 5: Create temporary KeyInfo for the CEK
        val cekInfo = createCEKInfo(cek)

        // Step 6: Construct AAD (same as encryption)
        val aad = constructAAD(header)

        // Step 7: Decrypt the ciphertext using the CEK
        val plaintext =
            try {
                keyManagerService.decrypt(
                    keyInfo = cekInfo,
                    ciphertext = ciphertext,
                    algorithm = encAlg,
                    iv = iv,
                    authTag = authTag,
                    additionalAuthenticatedData = aad,
                )
            } catch (expected: Throwable) {
                if (expected is CancellationException) throw expected
                return IdkResult.err(decryptionFailure("content-decrypt", "Decryption failed"))
            }

        // Step 8: RFC 7516 §4.1.3 decompression — when `zip=DEF`, INFLATE the plaintext (raw
        // RFC 1951, no zlib wrapper). Other `zip` values aren't IANA-registered — RFC 7516
        // says implementations MAY accept private values but we don't, so reject anything
        // other than DEF as a malformed JWE.
        val finalPlaintext =
            when (val zip = header.zip) {
                null -> {
                    plaintext
                }

                "DEF" -> {
                    try {
                        inflate(plaintext)
                    } catch (expected: Throwable) {
                        if (expected is CancellationException) throw expected
                        return IdkResult.err(decryptionFailure("decompression", "Failed to INFLATE compressed JWE plaintext"))
                    }
                }

                else -> {
                    return IdkResult.err(IdkError.fromString("Unsupported JWE zip algorithm: $zip (only DEF / RFC 1951 is supported)"))
                }
            }

        // Step 9: Return the result
        val result =
            JweDecryptionResult(
                plaintext = finalPlaintext,
                header = header,
                aad = aad,
            )

        return result.asOkResult()
    }

    /**
     * Constructs Additional Authenticated Data from JWE Protected Header
     * AAD = BASE64URL(UTF8(JWE Protected Header))
     */
    private fun constructAAD(header: JweHeader): ByteArray {
        val headerJson = cryptoJsonSerializer.encodeToString(JsonObject.serializer(), header.underlying)
        val base64Url = headerJson.encodeToByteArray().encodeTo(Encoding.BASE64URL)
        // Return as ASCII bytes
        return base64Url.encodeToByteArray()
    }

    /**
     * Creates a temporary KeyInfo for the Content Encryption Key (CEK)
     */
    private fun createCEKInfo(cek: ByteArray): KeyInfoType<*> {
        // Create a symmetric JWK for the CEK
        val jwk =
            Jwk(
                kty = JwaKeyType.oct, // Octet sequence (symmetric key)
                k = cek.encodeTo(Encoding.BASE64URL), // Base64url encoded key material
            )

        // Return KeyInfo with the symmetric key
        return KeyInfo(
            key = jwk,
            keyVisibility = KeyVisibility.PRIVATE,
        )
    }

    // Simple tuple class for destructuring
    private data class Tuple5<A, B, C, D, E>(
        val first: A,
        val second: B,
        val third: C,
        val fourth: D,
        val fifth: E,
    )

    /**
     * Performs ECDH-ES key agreement for decryption.
     *
     * For ECDH-ES (direct):
     * - Extracts epk from header
     * - Performs ECDH using our private key and the sender's ephemeral public key
     * - Applies Concat KDF to derive CEK directly
     *
     * For ECDH-ES+AxxxKW:
     * - Extracts epk from header
     * - Performs ECDH using our private key and the sender's ephemeral public key
     * - Applies Concat KDF to derive key-unwrapping key
     * - Unwraps the CEK using the derived key
     */
    private suspend fun performEcdhEsDecryption(
        keyAgreementAlg: KeyAgreementAlgorithm,
        encAlgStr: String,
        header: JweHeader,
        encryptedKey: ByteArray,
        decryptorKeyInfo: KeyInfoType<*>,
    ): IdkResult<ByteArray, IdkError> {
        // Extract ephemeral public key from header
        val epk =
            header.epk
                ?: return IdkResult.err(IdkError.fromString("epk (ephemeral public key) is required in header for ECDH-ES"))

        // Get apu and apv from header (if present)
        val apu = header.apu?.let { it.decodeFrom(Encoding.BASE64URL) } ?: ByteArray(0)
        val apv = header.apv?.let { it.decodeFrom(Encoding.BASE64URL) } ?: ByteArray(0)

        // Determine key length and algorithm ID for Concat KDF
        val keyLengthBits = ConcatKdf.getKeyLengthBits(keyAgreementAlg, encAlgStr)
        val algorithmId = ConcatKdf.getAlgorithmId(keyAgreementAlg, encAlgStr)

        if (epk.kty != JwaKeyType.EC || epk.x == null || epk.y == null) {
            return IdkResult.err(IdkError.fromString("epk must be an EC public key with x and y coordinates"))
        }

        // Route opaque handles through the selected KMS provider. Both ECDH and
        // Concat KDF run there, so neither private key material nor the raw shared
        // secret leaves the provider. Caller-supplied inline private JWKs retain
        // the local implementation.
        val derivedKey =
            if (decryptorKeyInfo.isProviderBackedReference()) {
                ecdhDeriveCommand
                    .execute(
                        EcdhDeriveArgs(
                            privateKeyInfo = decryptorKeyInfo,
                            publicKeyInfo = KeyInfo(key = epk, keyVisibility = KeyVisibility.PUBLIC),
                            algorithm = keyAgreementAlg,
                            mode = EcdhDeriveMode.CONCAT_KDF,
                            keyDataLen = keyLengthBits,
                            algorithmId = algorithmId,
                            partyUInfo = apu,
                            partyVInfo = apv,
                        ),
                    ).getOrElse { error -> return Err(error) }
                    .derivedSecret
            } else {
                val ourPrivateJwk =
                    decryptorKeyInfo.key as? Jwk
                        ?: return IdkResult.err(IdkError.fromString("Decryptor key must be a JWK for ECDH-ES"))
                if (ourPrivateJwk.kty != JwaKeyType.EC || ourPrivateJwk.d == null) {
                    return IdkResult.err(IdkError.fromString("Decryptor key must be a private EC key for ECDH-ES"))
                }
                val curve = EcdhUtils.getCurveFromJwk(ourPrivateJwk)
                val epkCurve = EcdhUtils.getCurveFromJwk(epk)
                if (curve != epkCurve) {
                    return IdkResult.err(IdkError.fromString("Curve mismatch: our key uses $curve but epk uses $epkCurve"))
                }
                val sharedSecret =
                    EcdhUtils.performKeyAgreementForDecryption(
                        ourPrivateKeyJwk = ourPrivateJwk,
                        senderEphemeralPublicKeyJwk = epk,
                        curve = curve,
                    )
                ConcatKdf.deriveKey(
                    sharedSecret = sharedSecret,
                    keyDataLen = keyLengthBits,
                    algorithmId = algorithmId,
                    apu = apu,
                    apv = apv,
                )
            }

        return if (keyAgreementAlg.requiresKeyWrap) {
            // ECDH-ES+AxxxKW: Use derived key to unwrap the CEK
            val cek = unwrapCekWithDerivedKey(derivedKey, encryptedKey, keyAgreementAlg)
            IdkResult.ok(cek)
        } else {
            // ECDH-ES: Use derived key directly as CEK
            IdkResult.ok(derivedKey)
        }
    }

    private fun KeyInfoType<*>.isProviderBackedReference(): Boolean =
        key == null &&
            !providerId.isNullOrBlank() &&
            (!alias.isNullOrBlank() || !kid.isNullOrBlank())

    /**
     * Unwraps the CEK using AES Key Wrap with the derived key.
     */
    private suspend fun unwrapCekWithDerivedKey(
        derivedKey: ByteArray,
        wrappedCek: ByteArray,
        algorithm: KeyAgreementAlgorithm,
    ): ByteArray {
        // Determine the AES-KW algorithm based on ECDH-ES variant
        val aesKwAlg =
            when (algorithm) {
                KeyAgreementAlgorithm.ECDH_ES_A128KW -> KeyWrapAlgorithm.A128KW
                KeyAgreementAlgorithm.ECDH_ES_A192KW -> KeyWrapAlgorithm.A192KW
                KeyAgreementAlgorithm.ECDH_ES_A256KW -> KeyWrapAlgorithm.A256KW
                else -> throw IllegalArgumentException("Algorithm $algorithm does not require key unwrapping")
            }

        // Create a KeyInfo for the derived key
        val derivedKeyInfo = createCEKInfo(derivedKey)

        // Use KMS to unwrap the CEK
        return keyManagerService.unwrapKey(
            unwrappingKeyInfo = derivedKeyInfo,
            wrappedKey = wrappedCek,
            algorithm = aesKwAlg,
        )
    }

    /**
     * Extracts the symmetric key from KeyInfo for direct encryption (alg="dir").
     *
     * For direct encryption, the shared symmetric key is used directly as the CEK.
     * The key must be a symmetric key (kty=oct) with the correct size for the
     * content encryption algorithm.
     *
     * @param keyInfo The decryptor's KeyInfo containing the symmetric key
     * @param encAlgStr The content encryption algorithm (e.g., "A256GCM")
     * @return The symmetric key bytes to use as CEK
     */
    @Suppress("MagicNumber")
    private fun extractSymmetricKeyForDir(
        keyInfo: KeyInfoType<*>,
        encAlgStr: String,
    ): IdkResult<ByteArray, IdkError> {
        // Get the key from KeyInfo
        val key =
            keyInfo.key
                ?: return IdkResult.err(IdkError.fromString("Decryptor key is required for direct encryption"))

        // Must be a JWK
        val jwk =
            key as? Jwk
                ?: return IdkResult.err(IdkError.fromString("Decryptor key must be a JWK for direct encryption"))

        // Must be a symmetric key (oct)
        if (jwk.kty != JwaKeyType.oct) {
            return IdkResult.err(
                IdkError.fromString(
                    "Direct encryption requires a symmetric key (kty=oct), got: ${jwk.kty}",
                ),
            )
        }

        // Extract the key material
        val kParameter =
            jwk.k
                ?: return IdkResult.err(
                    IdkError.fromString(
                        "Symmetric key must have 'k' parameter for direct encryption",
                    ),
                )

        val keyBytes = kParameter.decodeFrom(Encoding.BASE64URL)

        // Validate key size matches content encryption algorithm
        val expectedKeySize =
            when (encAlgStr) {
                "A128GCM" -> 16

                // 128 bits
                "A192GCM" -> 24

                // 192 bits
                "A256GCM" -> 32

                // 256 bits
                "A128CBC-HS256" -> 32

                // 256 bits (128 for encryption + 128 for MAC)
                "A192CBC-HS384" -> 48

                // 384 bits (192 for encryption + 192 for MAC)
                "A256CBC-HS512" -> 64

                // 512 bits (256 for encryption + 256 for MAC)
                else -> return IdkResult.err(
                    IdkError.fromString(
                        "Unsupported content encryption algorithm: $encAlgStr",
                    ),
                )
            }

        if (keyBytes.size != expectedKeySize) {
            return IdkResult.err(
                IdkError.fromString(
                    "Symmetric key size ${keyBytes.size} does not match expected size $expectedKeySize for $encAlgStr",
                ),
            )
        }

        return IdkResult.ok(keyBytes)
    }

    /**
     * Decrypts a JWE JSON General format message.
     *
     * For multi-recipient JWE, tries each recipient until one successfully decrypts.
     * First tries to match by kid, then falls back to trying all recipients.
     */
    private suspend fun decryptJweJsonGeneral(
        jwe: JweJsonGeneral,
        decryptor: ManagedIdentifierOptsOrResult,
        _appliedArgs: DecryptJweArgs,
    ): IdkResult<JweDecryptionResult, IdkError> {
        if (jwe.recipients.isEmpty()) {
            return IdkResult.err(IdkError.fromString("No recipients in JWE"))
        }

        val header =
            jwe.getProtectedHeader() ?: jwe.getUnprotectedHeader()
                ?: return IdkResult.err(IdkError.fromString("No header in JWE"))

        // Get algorithm strings
        val keyAlgStr = header.alg ?: return IdkResult.err(IdkError.fromString("alg header is required"))
        val encAlgStr = header.enc ?: return IdkResult.err(IdkError.fromString("enc header is required"))

        val encAlg =
            ContentEncryptionAlgorithm.fromIdentifier(encAlgStr)
                ?: return IdkResult.err(IdkError.fromString("Unsupported content encryption algorithm: $encAlgStr"))

        val keyAgreementAlg = KeyAgreementAlgorithm.fromIdentifier(keyAlgStr)
        val keyWrapAlg = KeyWrapAlgorithm.fromIdentifier(keyAlgStr)

        val decryptorReference =
            (decryptor as? ManagedOptsKeyInfo)
                ?.takeIf { it.lookup == it.identifier }
                ?.identifier
                ?.takeIf {
                    (keyAgreementAlg != null || (keyWrapAlg != null && keyWrapAlg != KeyWrapAlgorithm.DIR)) &&
                        it.isProviderBackedReference()
                }
        val decryptorKeyInfo =
            decryptorReference ?: run {
                val identifierResult = identifierService.resolve(decryptor)
                if (!identifierResult.isOk) {
                    logDecryptionRefusal("identifier-resolution", identifierResult.error)
                    return IdkResult.err(IdkError.fromDTO(identifierResult.error))
                }
                identifierResult.value.asResult().keyInfo
            }

        // Try to find matching recipient by kid first
        val decryptorKid = decryptorKeyInfo.kid
        val orderedRecipients =
            if (decryptorKid != null) {
                // Put matching recipient first, followed by others
                val matched = jwe.recipients.filter { r -> r.getHeader()?.kid == decryptorKid }
                val others = jwe.recipients.filter { r -> r.getHeader()?.kid != decryptorKid }
                matched + others
            } else {
                jwe.recipients.toList()
            }

        // Try each recipient until one succeeds
        var lastError: IdkError? = null
        for (recipient in orderedRecipients) {
            val encryptedKey = recipient.encrypted_key.decodeFrom(Encoding.BASE64URL)

            // For ECDH-ES, check if this recipient has an epk in per-recipient header
            val recipientHeader = recipient.getHeader()
            val effectiveHeader =
                if (keyAgreementAlg != null && recipientHeader?.epk != null) {
                    // Use per-recipient header's epk for ECDH-ES
                    JweHeader().apply {
                        header.underlying.forEach { (k, v) -> put(k, v) }
                        recipientHeader.epk?.let { epk = it }
                    }
                } else {
                    header
                }

            val cekResult =
                try {
                    if (keyAgreementAlg != null) {
                        performEcdhEsDecryption(
                            keyAgreementAlg = keyAgreementAlg,
                            encAlgStr = encAlgStr,
                            header = effectiveHeader,
                            encryptedKey = encryptedKey,
                            decryptorKeyInfo = decryptorKeyInfo,
                        )
                    } else if (keyWrapAlg != null) {
                        if (keyWrapAlg == KeyWrapAlgorithm.DIR) {
                            extractSymmetricKeyForDir(decryptorKeyInfo, encAlgStr)
                        } else {
                            try {
                                val cek =
                                    keyManagerService.unwrapKey(
                                        unwrappingKeyInfo = decryptorKeyInfo,
                                        wrappedKey = encryptedKey,
                                        algorithm = keyWrapAlg,
                                    )
                                IdkResult.ok(cek)
                            } catch (expected: Throwable) {
                                if (expected is CancellationException) throw expected
                                IdkResult.err(decryptionFailure("key-unwrap", "Key unwrapping failed"))
                            }
                        }
                    } else {
                        IdkResult.err(IdkError.fromString("Unsupported key encryption algorithm: $keyAlgStr"))
                    }
                } catch (expected: Throwable) {
                    if (expected is CancellationException) throw expected
                    IdkResult.err(decryptionFailure("cek-derivation", "CEK derivation failed"))
                }

            if (cekResult.isErr) {
                lastError = cekResult.error
                continue // Try next recipient
            }

            val cek = cekResult.value

            // Try decryption with this CEK
            val cekInfo = createCEKInfo(cek)
            val aad = constructAAD(header)

            try {
                val iv = jwe.iv.decodeFrom(Encoding.BASE64URL)
                val ciphertext = jwe.ciphertext.decodeFrom(Encoding.BASE64URL)
                val authTag = jwe.tag.decodeFrom(Encoding.BASE64URL)

                val plaintext =
                    keyManagerService.decrypt(
                        keyInfo = cekInfo,
                        ciphertext = ciphertext,
                        algorithm = encAlg,
                        iv = iv,
                        authTag = authTag,
                        additionalAuthenticatedData = aad,
                    )

                // RFC 7516 §4.1.3 decompression for the JSON-General multi-recipient path —
                // mirrors the compact path above. INFLATE raw DEFLATE (RFC 1951, no zlib
                // wrapper); reject any other `zip` value as malformed.
                val finalPlaintext =
                    when (val zip = header.zip) {
                        null -> {
                            plaintext
                        }

                        "DEF" -> {
                            try {
                                inflate(plaintext)
                            } catch (expected: Throwable) {
                                if (expected is CancellationException) throw expected
                                lastError = decryptionFailure("decompression", "Failed to INFLATE compressed JWE plaintext")
                                continue
                            }
                        }

                        else -> {
                            lastError = IdkError.fromString("Unsupported JWE zip algorithm: $zip (only DEF / RFC 1951 is supported)")
                            continue
                        }
                    }

                return JweDecryptionResult(
                    plaintext = finalPlaintext,
                    header = header,
                    aad = aad,
                ).asOkResult()
            } catch (expected: Throwable) {
                if (expected is CancellationException) throw expected
                lastError = decryptionFailure("content-decrypt", "Decryption failed")
                // Try next recipient
            }
        }

        // All recipients failed
        return IdkResult.err(lastError ?: IdkError.fromString("Failed to decrypt JWE with any recipient"))
    }
}
