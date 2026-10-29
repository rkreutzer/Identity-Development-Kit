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
 *
 */

package com.sphereon.crypto.core.generic

import com.sphereon.cbor.CborNumber
import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.compat.JsExportCompat
import com.sphereon.crypto.core.KeyType
import com.sphereon.crypto.core.KeyInfoType
import com.sphereon.crypto.core.cose.CoseKeyDTOType
import com.sphereon.crypto.core.cose.CoseKeyJsonDTOType
import com.sphereon.crypto.core.cose.CoseAlgorithm
import com.sphereon.crypto.core.cose.CoseCurve
import com.sphereon.crypto.core.cose.CoseKeyOperations
import com.sphereon.crypto.core.cose.CoseKeyTypeEnum
import com.sphereon.crypto.core.jose.JoseKeyOperations
import com.sphereon.crypto.core.jose.JwaAlgorithm
import com.sphereon.crypto.core.jose.JwaCurve
import com.sphereon.crypto.core.jose.JwaKeyType
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.Serializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlin.js.JsStatic
import kotlin.jvm.JvmStatic

@OptIn(ExperimentalSerializationApi::class)
internal object KeyTypeSerializer : KSerializer<KeyTypeMapping> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("KeyTypeMapping", PrimitiveKind.STRING)

    override fun serialize(
        encoder: Encoder,
        value: KeyTypeMapping,
    ) {
        encoder.encodeString(value::class.simpleName ?: value.toString())
    }

    override fun deserialize(decoder: Decoder): KeyTypeMapping {
        val value = decoder.decodeString()
        return KeyTypeMapping.fromValue(value) ?: throw SerializationException("Unknown key type: $value")
    }
}

/**
 * Represents a mapping between COSE key types and JWA key types.
 */
@JsExportCompat
@Serializable(with = KeyTypeSerializer::class)
sealed class KeyTypeMapping(
    private val coseKeyType: CoseKeyTypeEnum,
    private val joseKeyType: JwaKeyType,
) {
    /**
     * Represents a specific key type mapping for Octet Key Pairs (OKP).
     *
     * This object links the COSE key type `OKP` with its corresponding JWA key type `OKP`.
     * It ensures that cryptographic operations involving OKPs are correctly mapped between
     * COSE and JWA specifications.
     */
    object OKP : KeyTypeMapping(CoseKeyTypeEnum.OKP, JwaKeyType.OKP)

    /**
     * The `EC2` object is a specific instance of `KeyTypeMapping` for Elliptic Curve Keys (EC) as per COSE (CBOR Object Signing and Encryption) and JWA (JSON Web Algorithms) specifications
     * .
     *
     * This object maps the `CoseKeyType.EC2`, which represents Elliptic Curve Keys with x- and y-coordinate pairs, to the `JwaKeyType.EC`, which are used for cryptographic operations
     * .
     */
    object EC : KeyTypeMapping(CoseKeyTypeEnum.EC2, JwaKeyType.EC)

    /**
     * The `RSA` object represents the RSA key type mapping between COSE (CBOR Object Signing and Encryption)
     * and JWA (JSON Web Algorithms) key types.
     *
     * This object extends `KeyTypeMapping`, providing the specific association for RSA keys:
     * - COSE key type: `CoseKeyType.RSA`
     * - JWA key type: `JwaKeyType.RSA`
     *
     * The mapping allows for interoperability between different key representation standards, ensuring
     * RSA keys can be correctly interpreted and utilized within COSE and JWA frameworks.
     */
    object RSA : KeyTypeMapping(CoseKeyTypeEnum.RSA, JwaKeyType.RSA)

    /**
     * Represents a specific key type mapping for Symmetric keys (e.g., HMAC, AES).
     *
     * This object links the COSE key type `Symmetric` with its corresponding JWA key type `oct`.
     */
    object Symmetric : KeyTypeMapping(CoseKeyTypeEnum.Symmetric, JwaKeyType.oct)

    /**
     * Represents a key type for the 'jose' variable, used in the context of
     * JSON Object Signing and Encryption (JOSE).
     *
     * This variable typically holds key type information which can be used
     * for cryptographic operations including signing, encryption, and more.
     * It is part of the JOSE standard, which is designed to protect the
     * integrity and confidentiality of data transmitted between parties.
     */
    val jose = joseKeyType

    /**
     * Represents the cose key type that is used within the application.
     *
     * Initializes 'cose' with the designated COSE key type.
     */
    val cose = coseKeyType

    /**
     * This static object provides utility functions for converting between COSE and JOSE key types.
     */
    companion object {
        /**
         * Immutable list containing the key types for COSE: `OKP`, `EC2`, and `RSA`.
         *
         * This list is used to map between COSE and JOSE key types.
         *
         * Each element in the list represents a specific key type used in cryptographic operations.
         */
        @JsStatic
        val asList: List<KeyTypeMapping>
            get() = listOf(OKP, EC, RSA, Symmetric)

        // Safe (non-throwing) variants - return IdkResult

        /**
         * Safely converts a COSE key type to the corresponding JOSE key type.
         * @return IdkResult containing the JOSE key type, or an error if not found.
         */
        @JsStatic
        @JvmStatic
        fun tryToJose(cose: CoseKeyTypeEnum): IdkResult<JwaKeyType, IdkError> =
            asList
                .find { it.coseKeyType == cose || it.coseKeyType.toString() == cose.toString() }
                ?.joseKeyType
                ?.let { Ok(it) }
                ?: Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "COSE key type $cose not found"))

        /**
         * Safely converts a JWA key type to its corresponding COSE key type.
         * @return IdkResult containing the COSE key type, or an error if not found.
         */
        @JsStatic
        @JvmStatic
        fun tryToCose(jose: JwaKeyType): IdkResult<CoseKeyTypeEnum, IdkError> =
            asList
                .find { it.joseKeyType == jose || it.joseKeyType.toString() == jose.toString() }
                ?.coseKeyType
                ?.let { Ok(it) }
                ?: Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "JOSE key type $jose not found"))

        /**
         * Safely finds the corresponding KeyTypeMapping for the given JOSE key type.
         * @return IdkResult containing the KeyTypeMapping, or an error if not found.
         */
        @JsStatic
        @JvmStatic
        fun tryFromJose(jose: JwaKeyType): IdkResult<KeyTypeMapping, IdkError> =
            asList
                .find { it.joseKeyType == jose || it.joseKeyType.toString() == jose.toString() }
                ?.let { Ok(it) }
                ?: Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "JOSE key type $jose not found"))

        /**
         * Safely converts a COSE key type to the corresponding KeyTypeMapping.
         * @return IdkResult containing the KeyTypeMapping, or an error if not found.
         */
        @JsStatic
        @JvmStatic
        fun tryFromCose(cose: CoseKeyTypeEnum): IdkResult<KeyTypeMapping, IdkError> =
            asList
                .find { it.coseKeyType == cose || it.coseKeyType.toString() == cose.toString() }
                ?.let { Ok(it) }
                ?: Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "COSE key type $cose not found"))

        // Throwing variants - for backwards compatibility

        /**
         * Converts a given COSE key type to the corresponding JOSE key type.
         *
         * @param cose The `CoseKeyType` object that needs to be converted to a JOSE key type.
         * @throws IllegalArgumentException If the provided `CoseKeyType` does not have a corresponding JOSE key type.
         */
        @JsStatic
        @JvmStatic
        fun toJose(cose: CoseKeyTypeEnum) =
            tryToJose(cose).getOrElse {
                throw IllegalArgumentException(it.message.defaultMessage)
            }

        /**
         * Converts a given JWA key type to its corresponding COSE key type.
         *
         * @param jose The JwaKeyType representing the JSON Web Algorithm key type.
         * @return The corresponding CoseKeyType.
         * @throws IllegalArgumentException If the provided JWA key type cannot be found.
         */
        @JsStatic
        @JvmStatic
        fun toCose(jose: JwaKeyType) =
            tryToCose(jose).getOrElse {
                throw IllegalArgumentException(it.message.defaultMessage)
            }

        /**
         * Finds the corresponding `KeyTypeMapping` for the given `jose` key type.
         *
         * @param jose The `JwaKeyType` to find the corresponding `KeyTypeMapping`.
         * @throws IllegalArgumentException if the given `jose` key type is not found.
         */
        @JsStatic
        @JvmStatic
        fun fromJose(jose: JwaKeyType) =
            tryFromJose(jose).getOrElse {
                throw IllegalArgumentException(it.message.defaultMessage)
            }

        /**
         * Converts a given CoseKeyType to a specific instance if found in the list.
         *
         * @param cose the CoseKeyType to be converted.
         * @throws IllegalArgumentException if the specified CoseKeyType is not found in the list.
         */
        @JsStatic
        @JvmStatic
        fun fromCose(cose: CoseKeyTypeEnum) =
            tryFromCose(cose).getOrElse {
                throw IllegalArgumentException(it.message.defaultMessage)
            }

        /**
         * Safely converts a key type to a JOSE key type.
         * @return IdkResult containing the JOSE key type, or an error if conversion is not possible.
         */
        @JsStatic
        @JvmStatic
        fun tryToJoseKty(kty: Any): IdkResult<JwaKeyType, IdkError> =
            when (kty) {
                is String -> {
                    JwaKeyType.fromValue(kty)?.let { Ok(it) }
                        ?: Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Unknown JOSE key type: $kty"))
                }

                is Int -> {
                    CoseKeyTypeEnum.fromValue(kty.toLong())?.let { tryToJose(it) }
                        ?: Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Unknown COSE key type value: $kty"))
                }

                is CborNumber<*> -> {
                    CoseKeyTypeEnum.fromValue(kty.value.toLong())?.let { tryToJose(it) }
                        ?: Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Unknown COSE key type value: ${kty.value}"))
                }

                is CoseKeyTypeEnum -> {
                    tryToJose(kty)
                }

                is JwaKeyType -> {
                    Ok(kty)
                }

                else -> {
                    Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Cannot convert ${kty::class.simpleName} to JOSE key type"))
                }
            }

        /**
         * Safely converts a key type to a COSE key type.
         * @return IdkResult containing the COSE key type, or an error if conversion is not possible.
         */
        @JsStatic
        @JvmStatic
        fun tryToCoseKty(kty: Any): IdkResult<CoseKeyTypeEnum, IdkError> =
            when (kty) {
                is Long -> {
                    CoseKeyTypeEnum.fromValue(kty)?.let { Ok(it) }
                        ?: Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Unknown COSE key type value: $kty"))
                }

                is String -> {
                    JwaKeyType.fromValue(kty)?.let { tryToCose(it) }
                        ?: Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Unknown JOSE key type: $kty"))
                }

                is Int -> {
                    CoseKeyTypeEnum.fromValue(kty.toLong())?.let { Ok(it) }
                        ?: Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Unknown COSE key type value: $kty"))
                }

                is CborNumber<*> -> {
                    CoseKeyTypeEnum.fromValue(kty.value.toLong())?.let { Ok(it) }
                        ?: Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Unknown COSE key type value: ${kty.value}"))
                }

                is CoseKeyTypeEnum -> {
                    Ok(kty)
                }

                is JwaKeyType -> {
                    tryToCose(kty)
                }

                else -> {
                    Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Cannot convert ${kty::class.simpleName} to COSE key type"))
                }
            }

        /**
         * Converts a given key type (kty) to a corresponding JSON Web Algorithm (JWA) key type.
         *
         * @param kty any key type to be converted; it can be of type String, Int, CborNumber, CoseKeyType, or JwaKeyType
         * @return the converted JwaKeyType
         * @throws IllegalArgumentException if the given kty cannot be converted to a JwaKeyType
         */
        @JsStatic
        @JvmStatic
        fun toJoseKty(kty: Any): JwaKeyType =
            tryToJoseKty(kty).getOrElse {
                throw IllegalArgumentException(it.message.defaultMessage)
            }

        /**
         * Converts the given key type to a CoseKeyType.
         *
         * @param kty the key type to be converted. It can be of type String, Int, CborNumber, CoseKeyType, or JwaKeyType.
         * @return the corresponding CoseKeyType.
         * @throws IllegalArgumentException if the key type cannot be converted.
         */
        @JsStatic
        @JvmStatic
        fun toCoseKty(kty: Any): CoseKeyTypeEnum =
            tryToCoseKty(kty).getOrElse {
                throw IllegalArgumentException(it.message.defaultMessage)
            }

        /**
         * Converts a COSE key type value to a JOSE key type.
         *
         * @param kty An integer representing the COSE key type.
         * @return The equivalent JOSE key type.
         * @throws IllegalArgumentException If the COSE key type is unknown.
         */
        @JsStatic
        @JvmStatic
        fun toJoseKtyFromCose(kty: Number) = toJose(CoseKeyTypeEnum.fromValue(kty.toLong()))

        /**
         * Converts a JOSE key type (represented as a string) to the corresponding COSE key type.
         *
         * @param kty The JOSE key type as a string. This should match the values defined in the JwaKeyType enum.
         * @throws IllegalArgumentException If the provided `kty` is not a valid JOSE key type.
         */
        @JsStatic
        @JvmStatic
        fun toCoseKtyFromJose(kty: String) = toCose(JwaKeyType.fromValue(kty))

        @JsStatic
        @JvmStatic
        fun fromValue(value: String?): KeyTypeMapping? =
            asList.firstOrNull {
                val name = it::class.simpleName
                name != null && value != null && name.equals(value, ignoreCase = true)
            }
    }
}

/**
 * Converts the COSE key type (CoseKeyType) to the corresponding JOSE key type (JwaKeyType).
 *
 * This function utilizes the static mapping defined in KeyTypeMapping to find the equivalent JOSE key type
 * for the provided COSE key type. If the COSE key type does not have an associated JOSE key type in the
 * mapping, an IllegalArgumentException is thrown.
 *
 * @receiver The COSE key type to be converted.
 * @return The corresponding JOSE key type.
 * @throws IllegalArgumentException If the COSE key type cannot be mapped to a JOSE key type.
 */
@JsExportCompat
fun CoseKeyTypeEnum.toJoseKeyType() = KeyTypeMapping.toJose(this)

/**
 * Converts a `JwaKeyType` instance to the corresponding `CoseKeyType`.
 *
 * Uses the static mapping from `KeyTypeMapping` to find the appropriate
 * `CoseKeyType` for the given `JwaKeyType`.
 *
 * @return The associated `CoseKeyType`.
 * @throws IllegalArgumentException if no corresponding `CoseKeyType` is found.
 */
@JsExportCompat
fun JwaKeyType.toCoseKeyType() = KeyTypeMapping.toCose(this)

@OptIn(ExperimentalSerializationApi::class)
internal object SignatureAlgorithmSerializer : KSerializer<SignatureAlgorithm> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("SignatureAlgorithm", PrimitiveKind.STRING)

    override fun serialize(
        encoder: Encoder,
        value: SignatureAlgorithm,
    ) {
        encoder.encodeString(value::class.simpleName ?: value.toString())
    }

    override fun deserialize(decoder: Decoder): SignatureAlgorithm {
        val value = decoder.decodeString()
        // Every algorithm this serializer writes reads back, including the raw and key-agreement
        // ones a provider reports as capabilities but that have no JOSE/COSE mapping.
        return SignatureAlgorithm.serialized.find { it::class.simpleName == value }
            ?: throw SerializationException("Unknown signature algorithm: $value")
    }
}

/**
 * Represents a Signature Algorithm with various algorithm properties and identifiers.
 *
 * @property coseAlgorithm The COSE (CBOR Object Signing and Encryption) algorithm identifier.
 * @property joseAlgorithm The JOSE (JSON Object Signing and Encryption) algorithm identifier.
 * @property cryptoAlgorithm The cryptographic algorithm used for the signature.
 * @property digestAlgorithm The hash algorithm used in the signature process.
 * @property maskGenFunction The mask generation function algorithm.
 */
@JsExportCompat
@Serializable(with = SignatureAlgorithmSerializer::class)
sealed class SignatureAlgorithm(
    private val coseAlgorithm: CoseAlgorithm? = null, // we expose this as cose
    private val joseAlgorithm: JwaAlgorithm? = null, // we expose this as jose
    val cryptoAlgorithm: CryptoAlg,
    val digestAlgorithm: DigestAlg? = null,
    val curve: Curve?,
    val maskGenFunction: MaskGenFunction? = null,
) {
    /**
     * The `EdDSA` object represents an Elliptic Curve signature scheme using the Edwards-curve Digital Signature Algorithm.
     * It extends the `AlgorithmMapping` class, mapping the COSE (CBOR Object Signing and Encryption) algorithm 'EdDSA'
     * to the JWA (JSON Web Algorithms) algorithm 'EdDSA'.
     *
     * This class is used for cryptographic operations involving the EdDSA signature scheme, enabling interoperability
     * between different cryptographic frameworks and standards that support EdDSA.
     */
    object ED25519 : SignatureAlgorithm(CoseAlgorithm.EdDSA, JwaAlgorithm.EdDSA, cryptoAlgorithm = CryptoAlg.ED25519, curve = Curve.Ed25519)

    /**
     * EdDSA over Curve448-Goldilocks (Ed448) per RFC 8032 §5.2. JWA `crv = "Ed448"` (RFC 8037 update),
     * COSE `alg = -8 (EdDSA)` with `crv = 7 (Ed448)`. Signatures are 114 bytes.
     */
    object ED448 : SignatureAlgorithm(CoseAlgorithm.EdDSA, JwaAlgorithm.EdDSA, cryptoAlgorithm = CryptoAlg.ED448, curve = Curve.Ed448)

    /**
     * Represents the ECDSA algorithm with SHA-256 hashing.
     * It utilizes the P-256 curve for elliptic curve operations.
     * This algorithm is used for digital signatures and is mapped to the
     * COSE (CBOR Object Signing and Encryption) algorithm identifier -7 and the corresponding JWA (JSON Web Algorithm) identifier ES256.
     */
    object ECDSA_SHA256 : SignatureAlgorithm(
        CoseAlgorithm.ES256,
        JwaAlgorithm.ES256,
        cryptoAlgorithm = CryptoAlg.ECDSA,
        curve = Curve.P_256,
        digestAlgorithm = DigestAlg.SHA256,
    )

    /**
     * Represents the ECDSA with SHA-384 algorithm mapping.
     *
     * This object maps the COSE algorithm ES384 to the corresponding JWA algorithm.
     *
     * COSE Algorithm: ES384
     * JWA Algorithm: ES384
     */
    object ECDSA_SHA384 : SignatureAlgorithm(
        CoseAlgorithm.ES384,
        JwaAlgorithm.ES384,
        cryptoAlgorithm = CryptoAlg.ECDSA,
        curve = Curve.P_384,
        digestAlgorithm = DigestAlg.SHA384,
    )

    /**
     * Object representing the ES512 algorithm mapping.
     *
     * This object maps the COSE ES512 algorithm to the JWA ES512 algorithm.
     *
     * @see CoseAlgorithm.ES512
     * @see JwaAlgorithm.ES512
     */
    object ECDSA_SHA512 : SignatureAlgorithm(
        CoseAlgorithm.ES512,
        JwaAlgorithm.ES512,
        cryptoAlgorithm = CryptoAlg.ECDSA,
        curve = Curve.P_521,
        digestAlgorithm = DigestAlg.SHA512,
    )

    /**
     * An object that maps the COSE algorithm ES256K to the JWA algorithm ES256K.
     *
     * This object is a predefined instance of the AlgorithmMapping class that represents the
     * ECDSA secp256k1 curve with SHA-256 hashing algorithm. This is commonly used for digital
     * signatures in environments where both COSE (CBOR Object Signing and Encryption) and JWA
     * (JSON Web Algorithms) standards are supported.
     */
    object ES256K : SignatureAlgorithm(CoseAlgorithm.ES256K, JwaAlgorithm.ES256K, cryptoAlgorithm = CryptoAlg.ECDSA, curve = Curve.Secp256k1)

    /**
     * Placeholder for ECDH key agreement algorithm.
     *
     * Note: The COSE/JWA algorithm mappings are placeholders.
     * ECDH key agreement requires proper algorithm support in a future version.
     */
    object ECKA_DH_SHA256 : SignatureAlgorithm(
        CoseAlgorithm.HMAC256_256, // Placeholder - proper ECDH COSE algorithm needed
        JwaAlgorithm.ECDH_ES, // Placeholder - this is key agreement, not signature
        cryptoAlgorithm = CryptoAlg.ECDSA,
        curve = null,
        digestAlgorithm = DigestAlg.SHA256,
    )

    /**
     * This object represents the HS256 algorithm, which is a specific type of HMAC utilizing SHA-256.
     *
     * It extends the AlgorithmMapping class by mapping the COSE algorithm `CoseAlgorithm.HS256`
     * to the JWA algorithm `JwaAlgorithm.HS256`. This class can be used to handle cryptographic
     * operations that require HMAC with SHA-256.
     */
    object HMAC_SHA256 : SignatureAlgorithm(CoseAlgorithm.HMAC256_256, JwaAlgorithm.HS256, cryptoAlgorithm = CryptoAlg.HMAC, curve = null, digestAlgorithm = DigestAlg.SHA256)

    /**
     * HS384 object represents the algorithm mapping configuration for the HMAC with SHA-384 signature algorithm.
     * It extends the AlgorithmMapping class and links the COSE and JWA algorithm identifiers for HS384.
     */
    object HMAC_SHA384 : SignatureAlgorithm(CoseAlgorithm.HMAC384_384, JwaAlgorithm.HS384, cryptoAlgorithm = CryptoAlg.HMAC, curve = null, digestAlgorithm = DigestAlg.SHA384)

    /**
     * An object that provides a mapping between COSE and JOSE algorithms for the HS512 (HMAC with SHA-512) algorithm.
     *
     * This object is used to map the COSE algorithm identifier `CoseAlgorithm.HS512` to the
     * corresponding JOSE algorithm identifier `JwaAlgorithm.HS512`.
     */
    object HMAC_SHA512 : SignatureAlgorithm(CoseAlgorithm.HMAC512_512, JwaAlgorithm.HS512, cryptoAlgorithm = CryptoAlg.HMAC, curve = null, digestAlgorithm = DigestAlg.SHA512)

    /**
     * Object PS256 represents an algorithm mapping for the PS256 algorithm.
     * It extends the `AlgorithmMapping` class by associating COSE and JWA algorithm identifiers.
     *
     * @constructor
     * Initializes the algorithm mapping for the PS256 algorithm.
     *
     * @property coseAlgorithm
     * Identifier for the COSE algorithm.
     *
     * @property jwaAlgorithm
     * Identifier for the JWA algorithm.
     */
    object RSA_SSA_PSS_SHA256_MGF1 : SignatureAlgorithm(
        CoseAlgorithm.PS256,
        JwaAlgorithm.PS256,
        cryptoAlgorithm = CryptoAlg.RSA,
        curve = null,
        digestAlgorithm = DigestAlg.SHA256,
        maskGenFunction = MaskGenFunction.MGF1,
    )

    /**
     * PS384 object represents an algorithm mapping specifically for PS384 algorithm.
     *
     * It extends AlgorithmMapping class with the parameters:
     * - CoseAlgorithm.PS384
     * - JwaAlgorithm.PS384
     *
     * This class maps the PS384 algorithm supported by COSE (RFC 8152) to the PS384 algorithm
     * recognized by JOSE (RFC 7518).
     */
    object RSA_SSA_PSS_SHA384_MGF1 : SignatureAlgorithm(
        CoseAlgorithm.PS384,
        JwaAlgorithm.PS384,
        cryptoAlgorithm = CryptoAlg.RSA,
        curve = null,
        digestAlgorithm = DigestAlg.SHA384,
        maskGenFunction = MaskGenFunction.MGF1,
    )

    /**
     * Represents the RSASSA-PSS signature algorithm using SHA-512 hashing.
     *
     * Maps the COSE algorithm identifier for RSASSA-PSS with SHA-512 to the corresponding JWA algorithm.
     * Primarily used in contexts requiring RSASSA-PSS signature with SHA-512 as specified by COSE and JOSE standards.
     */
    object RSA_SSA_PSS_SHA512_MGF1 : SignatureAlgorithm(
        CoseAlgorithm.PS512,
        JwaAlgorithm.PS512,
        cryptoAlgorithm = CryptoAlg.RSA,
        curve = null,
        digestAlgorithm = DigestAlg.SHA512,
        maskGenFunction = MaskGenFunction.MGF1,
    )

    object RSA_RAW : SignatureAlgorithm(cryptoAlgorithm = CryptoAlg.RSA, curve = null)

    object RSA_SSA_PSS_RAW_MGF1 : SignatureAlgorithm(cryptoAlgorithm = CryptoAlg.RSA, curve = null, maskGenFunction = MaskGenFunction.MGF1)

    object RSA_SHA256 : SignatureAlgorithm(
        coseAlgorithm = CoseAlgorithm.RS256,
        joseAlgorithm = JwaAlgorithm.RS256,
        cryptoAlgorithm = CryptoAlg.RSA,
        curve = null,
        digestAlgorithm = DigestAlg.SHA256,
    )

    object RSA_SHA384 : SignatureAlgorithm(
        coseAlgorithm = CoseAlgorithm.RS384,
        joseAlgorithm = JwaAlgorithm.RS384,
        cryptoAlgorithm = CryptoAlg.RSA,
        curve = null,
        digestAlgorithm = DigestAlg.SHA384,
    )

    object RSA_SHA512 : SignatureAlgorithm(
        coseAlgorithm = CoseAlgorithm.RS512,
        joseAlgorithm = JwaAlgorithm.RS512,
        cryptoAlgorithm = CryptoAlg.RSA,
        curve = null,
        digestAlgorithm = DigestAlg.SHA512,
    )

    /*
        RSA_SHA3_256(CryptoAlg.RSA, DigestAlg.SHA3_256),
        RSA_SHA3_512(CryptoAlg.RSA, DigestAlg.SHA3_512),
        RSA_SSA_PSS_SHA3_256_MGF1(CryptoAlg.RSA, DigestAlg.SHA3_256, MaskGenFunction.MGF1),
        RSA_SSA_PSS_SHA3_512_MGF1(CryptoAlg.RSA, DigestAlg.SHA3_512, MaskGenFunction.MGF1),
     */

    /**
     * Holds the instance of the `joseAlgorithm` used for cryptographic operations.
     *
     * This variable is typically used to sign or verify tokens, ensuring the integrity
     * and authenticity of the transmitted data. The `joseAlgorithm` usually conforms
     * to the JSON Object Signing and Encryption (JOSE) standard, which specifies methods
     * for encryption, digital signatures, and other cryptographic processes.
     *
     * Ensure that the `joseAlgorithm` instance assigned to this variable is properly
     * configured and adheres to the security requirements of the application.
     */
    val jose = joseAlgorithm

    /**
     * The `cose` variable holds the value of the COSE (CBOR Object Signing and Encryption) algorithm.
     * This algorithm is used to perform cryptographic operations such as signing and encryption
     * on CBOR (Concise Binary Object Representation) encoded data.
     *
     * COSE provides a compact and efficient method for processing cryptographic data
     * in constrained environments.
     */
    val cose = coseAlgorithm

    /**
     * The Static object provides utility functions for converting between JOSE and COSE algorithms.
     */
    companion object {
        /**
         * A list of supported algorithm mappings used for COSE and JOSE algorithm conversions.
         *
         * This list includes both EdDSA curve variants (Ed25519 and Ed448), ES256K, ES256, ES384,
         * ES512, HS256, HS384, HS512, PS256, PS384, and PS512.  JOSE/COSE EdDSA lookup remains
         * family-ambiguous unless [tryFromJoseForKey] or [tryFromCoseForKey] is used.
         * It is utilized by functions to map between different cryptographic algorithm standards.
         */
        @JsStatic
        val asList: List<SignatureAlgorithm>
            get() =
                listOf(
                    ED25519,
                    ED448,
                    ES256K,
                    ECDSA_SHA256,
                    ECDSA_SHA384,
                    ECDSA_SHA512,
                    HMAC_SHA256,
                    HMAC_SHA384,
                    HMAC_SHA512,
                    RSA_SHA256,
                    RSA_SHA384,
                    RSA_SHA512,
                    RSA_SSA_PSS_SHA256_MGF1,
                    RSA_SSA_PSS_SHA384_MGF1,
                    RSA_SSA_PSS_SHA512_MGF1,
                )

        // Safe (non-throwing) variants - return IdkResult

        /**
         * Safely converts a COSE algorithm to its corresponding JOSE algorithm.
         * @return IdkResult containing the JOSE algorithm, or an error if not found.
         */
        @JsStatic
        @JvmStatic
        fun tryToJose(cose: CoseAlgorithm?): IdkResult<JwaAlgorithm, IdkError> {
            if (cose == null) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "COSE algorithm is null"))
            }
            return tryFromCose(cose).let { result ->
                when {
                    result.isOk -> {
                        result.value.joseAlgorithm?.let { Ok(it) }
                            ?: Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "COSE algorithm $cose has no JOSE equivalent"))
                    }

                    else -> {
                        Err(result.error)
                    }
                }
            }
        }

        /**
         * Safely converts a JWA algorithm to the corresponding COSE algorithm.
         * @return IdkResult containing the COSE algorithm, or an error if not found.
         */
        @JsStatic
        @JvmStatic
        fun tryToCose(jose: JwaAlgorithm?): IdkResult<CoseAlgorithm, IdkError> {
            if (jose == null) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "JOSE algorithm is null"))
            }
            return tryFromJose(jose).let { result ->
                when {
                    result.isOk -> {
                        result.value.coseAlgorithm?.let { Ok(it) }
                            ?: Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "JOSE algorithm $jose has no COSE equivalent"))
                    }

                    else -> {
                        Err(result.error)
                    }
                }
            }
        }

        /**
         * Safely retrieves the algorithm mapping for the given JOSE algorithm.
         * @return IdkResult containing the SignatureAlgorithm mapping, or an error if not found.
         */
        @JsStatic
        @JvmStatic
        fun tryFromJose(jose: JwaAlgorithm?): IdkResult<SignatureAlgorithm, IdkError> {
            if (jose == null) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "JOSE algorithm is null"))
            }
            return asList
                .find { it.joseAlgorithm == jose || it.joseAlgorithm.toString() == jose.toString() }
                ?.let { Ok(it) }
                ?: Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "JOSE algorithm $jose not found"))
        }

        /**
         * Safely retrieves the algorithm mapping for the given COSE algorithm.
         * @return IdkResult containing the SignatureAlgorithm mapping, or an error if not found.
         */
        @JsStatic
        @JvmStatic
        fun tryFromCose(cose: CoseAlgorithm?): IdkResult<SignatureAlgorithm, IdkError> {
            if (cose == null) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "COSE algorithm is null"))
            }
            return asList
                .find { it.coseAlgorithm == cose || it.coseAlgorithm.toString() == cose.toString() }
                ?.let { Ok(it) }
                ?: Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "COSE algorithm $cose not found"))
        }

        /**
         * Resolves a JOSE algorithm against already-resolved key metadata.
         *
         * JOSE EdDSA is a family identifier: it does not identify whether an OKP key is
         * Ed25519 or Ed448.  The legacy [tryFromJose] mapping intentionally remains generic for
         * callers that do not have a key.  Security-sensitive signing and verification callers
         * must use this resolver so that resolved key material always supplies the curve; only a
         * metadata-only provider result with an explicit OKP type may use an authoritative
         * Ed25519/Ed448 algorithm, and contradictory metadata is rejected.
         */
        @JsStatic
        @JvmStatic
        fun tryFromJoseForKey(
            jose: JwaAlgorithm?,
            keyInfo: KeyInfoType<*>?,
        ): IdkResult<SignatureAlgorithm, IdkError> {
            if (jose == null) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "JOSE algorithm is null"))
            }
            if (jose != JwaAlgorithm.EdDSA) {
                return tryFromJose(jose)
            }
            return tryResolveEdDsaForKey(keyInfo)
        }

        /** Resolves COSE EdDSA (-8) using the resolved OKP curve, never by list order. */
        @JsStatic
        @JvmStatic
        fun tryFromCoseForKey(
            cose: CoseAlgorithm?,
            keyInfo: KeyInfoType<*>?,
        ): IdkResult<SignatureAlgorithm, IdkError> {
            if (cose == null) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "COSE algorithm is null"))
            }
            if (cose != CoseAlgorithm.EdDSA) {
                return tryFromCose(cose)
            }
            return tryResolveEdDsaForKey(keyInfo)
        }

        private fun tryResolveEdDsaForKey(keyInfo: KeyInfoType<*>?): IdkResult<SignatureAlgorithm, IdkError> {
            if (keyInfo == null) {
                return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message = "EdDSA is ambiguous without resolved OKP curve or authoritative signature algorithm",
                    ),
                )
            }

            val key = keyInfo.key
            val actualKeyType = key?.let { runCatching { it.getKeyType() }.getOrNull() }
            val declaredKeyType = keyInfo.keyType
            if (actualKeyType != null && declaredKeyType != null && actualKeyType != declaredKeyType) {
                return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message = "resolved key type '$actualKeyType' contradicts declared key type '$declaredKeyType'",
                    ),
                )
            }
            if ((actualKeyType != null && actualKeyType != KeyTypeMapping.OKP) ||
                (actualKeyType == null && declaredKeyType != null && declaredKeyType != KeyTypeMapping.OKP)
            ) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "EdDSA requires an OKP key"))
            }
            if (key == null && declaredKeyType != KeyTypeMapping.OKP) {
                return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message = "metadata-only EdDSA requires resolved key type OKP",
                    ),
                )
            }

            val contradictsEdDsa = when (key) {
                is com.sphereon.crypto.core.jose.JwkType -> {
                    val jwkAlgorithm = key.alg
                    jwkAlgorithm != null && jwkAlgorithm != JwaAlgorithm.EdDSA
                }
                is CoseKeyJsonDTOType -> {
                    val coseAlgorithm = key.alg
                    coseAlgorithm != null && coseAlgorithm != CoseAlgorithm.EdDSA
                }
                is CoseKeyDTOType -> {
                    val coseAlgorithm = key.alg
                    coseAlgorithm?.let { algorithm -> algorithm.value.toInt() != CoseAlgorithm.EdDSA.value } == true
                }
                else -> false
            }
            if (contradictsEdDsa) {
                return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message = "resolved key algorithm contradicts EdDSA",
                    ),
                )
            }

            val curve = key?.let {
                runCatching {
                    when (it) {
                        is com.sphereon.crypto.core.jose.JwkType -> it.crv?.let(Curve::fromJose)
                        is CoseKeyJsonDTOType -> it.crv?.let(Curve::fromCose)
                        is CoseKeyDTOType -> it.crv?.let { c -> Curve.fromCose(com.sphereon.crypto.core.cose.CoseCurve.fromValue(c.value.toInt())) }
                        else -> null
                    }
                }.getOrElse {
                    return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "invalid resolved EdDSA curve: ${it.message}"))
                }
            }
            val byCurve = when (curve) {
                Curve.Ed25519 -> SignatureAlgorithm.ED25519
                Curve.Ed448 -> SignatureAlgorithm.ED448
                null -> null
                else -> return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "EdDSA requires Ed25519 or Ed448, resolved '$curve'"))
            }
            if (key != null && byCurve == null) {
                return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message = "resolved EdDSA key material must declare an Ed25519 or Ed448 curve",
                    ),
                )
            }
            val authoritative = keyInfo.signatureAlgorithm
            if (authoritative != null && authoritative != SignatureAlgorithm.ED25519 && authoritative != SignatureAlgorithm.ED448) {
                return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message = "resolved signature algorithm '$authoritative' contradicts EdDSA",
                    ),
                )
            }
            if (byCurve != null && authoritative != null && byCurve != authoritative) {
                return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message = "resolved EdDSA curve '$curve' contradicts authoritative signature algorithm '$authoritative'",
                    ),
                )
            }
            return (byCurve ?: authoritative)?.let(::Ok)
                ?: Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message = "EdDSA is ambiguous without resolved OKP curve or authoritative signature algorithm",
                    ),
                )
        }

        /**
         * Safely converts a provided algorithm representation to a `JwaAlgorithm`.
         * @return IdkResult containing the JwaAlgorithm, or an error if conversion is not possible.
         */
        @JsStatic
        @JvmStatic
        fun tryToJoseAlg(alg: Any?): IdkResult<JwaAlgorithm, IdkError> {
            if (alg == null) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Algorithm is null"))
            }
            return when (alg) {
                is String -> {
                    JwaAlgorithm.fromValue(alg)?.let { Ok(it) }
                        ?: Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Unknown JOSE algorithm: $alg"))
                }

                is Int -> {
                    tryToJoseAlgFromCose(alg)
                }

                is CborNumber<*> -> {
                    tryToJoseAlgFromCose(alg.value.toInt())
                }

                is CoseAlgorithm -> {
                    tryToJose(alg)
                }

                is JwaAlgorithm -> {
                    Ok(alg)
                }

                else -> {
                    Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Cannot convert ${alg::class.simpleName} to JOSE algorithm"))
                }
            }
        }

        /**
         * Safely converts a given algorithm representation to a `CoseAlgorithm`.
         * @return IdkResult containing the CoseAlgorithm, or an error if conversion is not possible.
         */
        @JsStatic
        @JvmStatic
        fun tryToCoseAlg(alg: Any?): IdkResult<CoseAlgorithm, IdkError> {
            if (alg == null) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Algorithm is null"))
            }
            return when (alg) {
                is String -> {
                    tryToCoseAlgFromJose(alg)
                }

                is Int -> {
                    CoseAlgorithm.fromValue(alg)?.let { Ok(it) }
                        ?: Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Unknown COSE algorithm value: $alg"))
                }

                is CborNumber<*> -> {
                    CoseAlgorithm.fromValue(alg.value.toInt())?.let { Ok(it) }
                        ?: Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Unknown COSE algorithm value: ${alg.value}"))
                }

                is CoseAlgorithm -> {
                    Ok(alg)
                }

                is JwaAlgorithm -> {
                    tryToCose(alg)
                }

                else -> {
                    Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Cannot convert ${alg::class.simpleName} to COSE algorithm"))
                }
            }
        }

        /**
         * Safely converts a COSE algorithm identifier to the corresponding JOSE algorithm.
         * @return IdkResult containing the JOSE algorithm, or an error if not found.
         */
        @JsStatic
        @JvmStatic
        fun tryToJoseAlgFromCose(algorithm: Int?): IdkResult<JwaAlgorithm, IdkError> {
            if (algorithm == null) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Algorithm is null"))
            }
            val coseAlg =
                CoseAlgorithm.fromValue(algorithm)
                    ?: return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Unknown COSE algorithm value: $algorithm"))
            return tryToJose(coseAlg)
        }

        /**
         * Safely converts a JOSE algorithm name to its corresponding COSE algorithm.
         * @return IdkResult containing the COSE algorithm, or an error if not found.
         */
        @JsStatic
        @JvmStatic
        fun tryToCoseAlgFromJose(algorithm: String?): IdkResult<CoseAlgorithm, IdkError> {
            if (algorithm == null) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Algorithm is null"))
            }
            val joseAlg =
                JwaAlgorithm.fromValue(algorithm)
                    ?: return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Unknown JOSE algorithm: $algorithm"))
            return tryToCose(joseAlg)
        }

        // Throwing variants - for backwards compatibility

        /**
         * Converts a given COSE algorithm to its corresponding JOSE algorithm.
         *
         * @param cose The COSE algorithm to be converted.
         * @throws IllegalArgumentException if the given COSE algorithm does not have a corresponding JOSE algorithm.
         */
        @JsStatic
        @JvmStatic
        fun toJose(cose: CoseAlgorithm?) =
            tryToJose(cose).getOrElse {
                throw IllegalArgumentException(it.message.defaultMessage)
            }

        /**
         * Converts a given JWA algorithm to the corresponding COSE algorithm.
         *
         * @param jose The JWA algorithm to be converted.
         * @throws IllegalArgumentException if the provided JWA algorithm is not found in the mapping.
         * @return The corresponding COSE algorithm.
         */
        @JsStatic
        @JvmStatic
        fun toCose(jose: JwaAlgorithm?) =
            tryToCose(jose).getOrElse {
                throw IllegalArgumentException(it.message.defaultMessage)
            }

        /**
         * Retrieves the algorithm mapping matching the given JSON Web Algorithm (JWA) algorithm.
         *
         * @param jose The JWA algorithm to match.
         * @throws IllegalArgumentException if the algorithm is not found.
         */
        @JsStatic
        @JvmStatic
        fun fromJose(jose: JwaAlgorithm?) =
            tryFromJose(jose).getOrElse {
                throw IllegalArgumentException(it.message.defaultMessage)
            }

        /** Resolves JOSE EdDSA against the resolved key's curve or authoritative algorithm. */
        @JsStatic
        @JvmStatic
        fun fromJoseForKey(
            jose: JwaAlgorithm?,
            keyInfo: KeyInfoType<*>?,
        ) =
            tryFromJoseForKey(jose, keyInfo).getOrElse {
                throw IllegalArgumentException(it.message.defaultMessage)
            }

        /**
         * Converts a given COSE algorithm to its corresponding internal representation.
         *
         * @param cose the COSE algorithm to be converted.
         * @throws IllegalArgumentException if the algorithm is not found.
         */
        @JsStatic
        @JvmStatic
        fun fromCose(cose: CoseAlgorithm?) =
            tryFromCose(cose).getOrElse {
                throw IllegalArgumentException(it.message.defaultMessage)
            }

        /** Resolves COSE EdDSA (-8) against the resolved key's curve or authoritative algorithm. */
        @JsStatic
        @JvmStatic
        fun fromCoseForKey(
            cose: CoseAlgorithm?,
            keyInfo: KeyInfoType<*>?,
        ) =
            tryFromCoseForKey(cose, keyInfo).getOrElse {
                throw IllegalArgumentException(it.message.defaultMessage)
            }

        /**
         * Converts a provided algorithm representation to a `JwaAlgorithm`.
         *
         * @param alg The algorithm value to be converted. It can be of type `String`, `Int`, `CborNumber`, `CoseAlgorithm`, or `JwaAlgorithm`.
         * @return The corresponding `JwaAlgorithm`.
         * @throws IllegalArgumentException if the provided algorithm cannot be converted to a `JwaAlgorithm`.
         */
        @JsStatic
        @JvmStatic
        fun toJoseAlg(alg: Any?): JwaAlgorithm =
            tryToJoseAlg(alg).getOrElse {
                throw IllegalArgumentException(it.message.defaultMessage)
            }

        /**
         * Converts a given algorithm representation to a `CoseAlgorithm`.
         *
         * @param alg The algorithm to be converted. It can be of type `String`, `Int`, `CborNumber`, `CoseAlgorithm`, or `JwaAlgorithm`.
         * @return The corresponding `CoseAlgorithm` for the provided algorithm representation.
         * @throws IllegalArgumentException If the algorithm cannot be converted to a `CoseAlgorithm`.
         */
        @JsStatic
        @JvmStatic
        fun toCoseAlg(alg: Any?): CoseAlgorithm =
            tryToCoseAlg(alg).getOrElse {
                throw IllegalArgumentException(it.message.defaultMessage)
            }

        /**
         * Converts a COSE (CBOR Object Signing and Encryption) algorithm identifier to the corresponding JOSE (JSON Object Signing and Encryption) algorithm.
         *
         * @param algorithm The integer value representing a COSE algorithm.
         * @throws IllegalArgumentException If the COSE algorithm identifier is not recognized.
         * @return The equivalent JOSE algorithm.
         */
        @JsStatic
        @JvmStatic
        fun toJoseAlgFromCose(algorithm: Int?) =
            tryToJoseAlgFromCose(algorithm).getOrElse {
                throw IllegalArgumentException(it.message.defaultMessage)
            }

        /**
         * Converts a JOSE algorithm name to its corresponding COSE algorithm.
         *
         * @param algorithm The name of the JOSE algorithm to be converted.
         * @throws IllegalArgumentException If the provided JOSE algorithm name is not found.
         * @return The corresponding COSE algorithm.
         */
        @JsStatic
        @JvmStatic
        fun toCoseAlgFromJose(algorithm: String?): CoseAlgorithm =
            tryToCoseAlgFromJose(algorithm).getOrElse {
                throw IllegalArgumentException(it.message.defaultMessage)
            }

        @JsStatic
        @JvmStatic
        fun fromValue(value: String): SignatureAlgorithm? = asList.find { it::class.simpleName == value }

        /**
         * Every defined algorithm, for the wire format: [asList] plus the raw RSA and key-agreement
         * algorithms, which carry no JOSE/COSE mapping but are reported as provider capabilities.
         */
        internal val serialized: List<SignatureAlgorithm>
            get() = asList + listOf(RSA_RAW, RSA_SSA_PSS_RAW_MGF1, ECKA_DH_SHA256)
    }
}

/**
 * Converts the CoseAlgorithm to its corresponding JOSE (JSON Object Signing and Encryption)
 * signature algorithm representation.
 *
 * @receiver The COSE (CBOR Object Signing and Encryption) algorithm to be converted.
 * @return The corresponding JOSE signature algorithm as defined in the AlgorithmMapping.
 */
@JsExportCompat
fun CoseAlgorithm.toJoseSignatureAlgorithm() = SignatureAlgorithm.toJose(this)

/**
 * Converts a JWA (JSON Web Algorithm) algorithm to a COSE (CBOR Object Signing and Encryption) algorithm.
 *
 * This function utilizes a static mapping to retrieve the corresponding COSE algorithm for the provided JWA algorithm.
 *
 * @receiver The JWA algorithm to be converted.
 * @return The corresponding COSE algorithm.
 * @throws IllegalArgumentException if no corresponding COSE algorithm is found.
 */
@JsExportCompat
fun JwaAlgorithm.toCoseAlgorithm() = SignatureAlgorithm.toCose(this)

// TODO Enc algos

/**
 * Represents a mapping of COSE and JOSE elliptic curves for cryptography.
 *
 * @property coseCurve The COSE curve associated with the mapping.
 * @property joseCurve The JOSE curve associated with the mapping.
 */
@JsExportCompat
@Serializable
sealed class Curve(
    private val coseCurve: CoseCurve,
    private val joseCurve: JwaCurve,
) {
    /**
     * Object representation of P-256 elliptic curve.
     *
     * This object maps the P-256 elliptic curve to its corresponding COSE and JWA curve identifiers.
     * It extends the CurveMapping class using P-256 values from both COSE and JWA curve enumerations.
     */
    @Serializable
    @SerialName("P-256")
    object P_256 : Curve(CoseCurve.P_256, JwaCurve.P_256)

    /**
     * Represents the P-384 elliptic curve mapping between COSE (CBOR Object Signing and Encryption) and JOSE (JSON Object Signing and Encryption).
     */
    @Serializable
    @SerialName("P-384")
    object P_384 : Curve(CoseCurve.P_384, JwaCurve.P_384)

    /**
     * Object representing the P-521 elliptic curve.
     *
     * This object is a part of the CurveMapping sealed class and specifies
     * the mapping for the P-521 curve corresponding to both COSE (CBOR Object Signing and
     * Encryption) and JWA (JSON Web Algorithms).
     *
     * @see Curve
     * @see CoseCurve
     * @see JwaCurve
     */
    @Serializable
    @SerialName("P-521")
    object P_521 : Curve(CoseCurve.P_521, JwaCurve.P_521)

    /**
     * Represents the Secp256k1 elliptic curve mapping used in various cryptographic standards.
     *
     * This object associates the COSE curve Secp256k1 with the JOSE curve Secp256k1.
     *
     * The Secp256k1 curve is widely used in cryptocurrencies and decentralized applications.
     */
    @Serializable
    @SerialName("secp256k1")
    object Secp256k1 : Curve(CoseCurve.secp256k1, JwaCurve.Secp256k1)

    /**
     * The `Ed25519` object represents the Ed25519 elliptic curve mapping.
     *
     * This object is part of the `CurveMapping` hierarchy and it specifically maps the COSE curve `Ed25519` to
     * the corresponding JWA curve `Ed25519`.
     */
    @Serializable
    @SerialName("Ed25519")
    object Ed25519 : Curve(CoseCurve.Ed25519, JwaCurve.Ed25519)

    /**
     * Ed448 (Curve448-Goldilocks) signing curve per RFC 8032 §5.2.
     */
    object Ed448 : Curve(CoseCurve.Ed448, JwaCurve.Ed448)

    /**
     * Represents the X25519 curve mapping for both COSE and JWA standards.
     * This object is used to map the X25519 curve within the `CurveMapping` sealed class.
     */
    @Serializable
    @SerialName("X25519")
    object X25519 : Curve(CoseCurve.X25519, JwaCurve.X25519)

    /**
     * X448 (Curve448-Goldilocks) Diffie-Hellman key-agreement curve per RFC 7748 §5.
     */
    object X448 : Curve(CoseCurve.X448, JwaCurve.X448)

    /**
     * Represents the JWA curve associated with the specific CurveMapping instance.
     */
    val jose = joseCurve

    /**
     * Represents the COSE curve associated with this instance of `CurveMapping`.
     *
     * The COSE (CBOR Object Signing and Encryption) curve is an elliptic curve
     * cryptography parameter defined by the COSE standard.
     */
    val cose = coseCurve

    /**
     * Object that provides static methods and properties for mapping
     * between CoseCurve and JwaCurve.
     */
    companion object {
        /**
         * A list containing instances of various elliptic curve mappings used for cryptographic operations.
         * This list includes the following curves:
         * - P_256
         * - P_384
         * - P_521
         * - Secp256k1
         * - Ed25519
         * - Ed448
         * - X25519
         * - X448
         *
         * The list is used for performing lookups and conversions between COSE and JOSE curve representations.
         */
        @JsStatic
        val asList: List<Curve>
            get() = listOf(P_256, P_384, P_521, Secp256k1, Ed25519, Ed448, X25519, X448)

        // Safe (non-throwing) variants - return IdkResult

        /**
         * Safely retrieves the Curve mapping for the given JOSE curve.
         * @return IdkResult containing the Curve mapping, or an error if not found.
         */
        @JsStatic
        @JvmStatic
        fun tryFromJose(jose: JwaCurve?): IdkResult<Curve, IdkError> {
            if (jose == null) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "JOSE curve is null"))
            }
            return asList
                .find { it.joseCurve == jose || it.joseCurve.toString() == jose.toString() }
                ?.let { Ok(it) }
                ?: Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "JOSE curve $jose not found"))
        }

        /**
         * Safely retrieves the Curve mapping for the given COSE curve.
         * @return IdkResult containing the Curve mapping, or an error if not found.
         */
        @JsStatic
        @JvmStatic
        fun tryFromCose(cose: CoseCurve?): IdkResult<Curve, IdkError> {
            if (cose == null) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "COSE curve is null"))
            }
            return asList
                .find { it.coseCurve == cose || it.coseCurve.toString() == cose.toString() }
                ?.let { Ok(it) }
                ?: Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "COSE curve $cose not found"))
        }

        /**
         * Safely converts a COSE curve to its corresponding JOSE curve.
         * @return IdkResult containing the JOSE curve, or an error if not found.
         */
        @JsStatic
        @JvmStatic
        fun tryToJose(cose: CoseCurve?): IdkResult<JwaCurve, IdkError> =
            tryFromCose(cose).let { result ->
                when {
                    result.isOk -> Ok(result.value.joseCurve)
                    else -> Err(result.error)
                }
            }

        /**
         * Safely converts a JOSE curve to its corresponding COSE curve.
         * @return IdkResult containing the COSE curve, or an error if not found.
         */
        @JsStatic
        @JvmStatic
        fun tryToCose(jose: JwaCurve?): IdkResult<CoseCurve, IdkError> =
            tryFromJose(jose).let { result ->
                when {
                    result.isOk -> Ok(result.value.coseCurve)
                    else -> Err(result.error)
                }
            }

        // Throwing variants - for backwards compatibility

        @JsStatic
        @JvmStatic
        fun fromJose(jose: JwaCurve?) =
            tryFromJose(jose).getOrElse {
                throw IllegalArgumentException(it.message.defaultMessage)
            }

        @JsStatic
        @JvmStatic
        fun fromCose(cose: CoseCurve?) =
            tryFromCose(cose).getOrElse {
                throw IllegalArgumentException(it.message.defaultMessage)
            }

        /**
         * Converts a given COSE curve to its corresponding JOSE curve.
         *
         * @param cose The COSE curve that needs to be converted.
         * @throws IllegalArgumentException if the provided COSE curve is not found.
         * @return The corresponding JOSE curve.
         */
        @JsStatic
        @JvmStatic
        fun toJose(cose: CoseCurve) = fromCose(cose).joseCurve

        /**
         * Converts a JwaCurve to its corresponding CoseCurve.
         *
         * @param jose The JwaCurve to be converted.
         * @throws IllegalArgumentException if the specified jose curve is not found.
         * @return The corresponding CoseCurve.
         */
        @JsStatic
        @JvmStatic
        fun toCose(jose: JwaCurve) = fromJose(jose).coseCurve
    }
}

/**
 * Maps the current `CoseCurve` to its corresponding `JwaCurve`.
 *
 * This function utilizes the `CurveMapping.toJose` method to find the
 * equivalent `JwaCurve` for the `CoseCurve` instance it is called on.
 *
 * @receiver The `CoseCurve` instance to be mapped to a `JwaCurve`.
 * @return The corresponding `JwaCurve` instance.
 * @throws IllegalArgumentException If the `CoseCurve` instance does not have a
 * corresponding `JwaCurve`.
 */
@JsExportCompat
fun CoseCurve.toJoseCurve() = Curve.toJose(this)

/**
 * Converts the JWA elliptic curve identifier to its corresponding COSE curve identifier.
 *
 * This extension function uses the `CurveMapping.toCose` method to perform the
 * conversion. If the conversion is unsuccessful, an IllegalArgumentException is thrown.
 *
 * @return the corresponding COSE curve identifier
 * @throws IllegalArgumentException if the JWA curve identifier is not found in the mapping
 */
@JsExportCompat
fun JwaCurve.toCoseCurve() = Curve.toCose(this)

@OptIn(ExperimentalSerializationApi::class)
internal object KeyOperationsSerializer : KSerializer<KeyOperations> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("KeyOperations", PrimitiveKind.STRING)

    override fun serialize(
        encoder: Encoder,
        value: KeyOperations,
    ) {
        encoder.encodeString(KeyOperations.toValue(value))
    }

    override fun deserialize(decoder: Decoder): KeyOperations {
        val value = decoder.decodeString()
        return return KeyOperations.fromValue(value)
    }
}

/**
 * A sealed class representing the mapping of COSE key operations to JOSE key operations.
 *
 * @property coseKeyOperations The COSE key operation associated with this mapping.
 * @property joseKeyOperations The JOSE key operation associated with this mapping.
 */
@JsExportCompat
@Serializable(with = KeyOperationsSerializer::class)
sealed class KeyOperations(
    private val coseKeyOperations: CoseKeyOperations,
    private val joseKeyOperations: JoseKeyOperations,
) {
    /**
     * Represents the key operation for key wrap encryption within the context of COSE (CBOR Object Signing and Encryption)
     * and JOSE (JSON Object Signing and Encryption) standards.
     *
     * This singleton object maps the COSE key operation for wrapping keys (`CoseKeyOperations.WRAP_KEY`)
     * to the corresponding JOSE key operation (`JoseKeyOperations.WRAP_KEY`).
     */
    object WRAP_KEY : KeyOperations(CoseKeyOperations.WRAP_KEY, JoseKeyOperations.WRAP_KEY)

    /**
     * Object `DERIVE_KEY` represents a key operation for deriving keys.
     * It is a mapping between COSE and JOSE key operations that indicate
     * the key is used for deriving other keys. Requires private key fields.
     */
    object DERIVE_KEY : KeyOperations(CoseKeyOperations.DERIVE_KEY, JoseKeyOperations.DERIVE_KEY)

    /**
     * Represents a specific key operation for unwrapping a key as defined in COSE and JOSE standards.
     *
     * It maps the `UNWRAP_KEY` operation from COSE (`CoseKeyOperations.UNWRAP_KEY`) and JOSE (`JoseKeyOperations.UNWRAP_KEY`).
     *
     * The key is used for key wrap decryption and requires private key fields.
     */
    object UNWRAP_KEY : KeyOperations(CoseKeyOperations.UNWRAP_KEY, JoseKeyOperations.UNWRAP_KEY)

    /**
     * Represents the mapping for the signing key operation.
     * This object associates the COSE and JOSE key operations used for signing.
     */
    object SIGN : KeyOperations(CoseKeyOperations.SIGN, JoseKeyOperations.SIGN)

    /**
     * Represents a cryptographic operation for verification of signatures.
     *
     * This object is part of the KeyOperationsMapping class and maps the COSE key operation VERIFY
     * with the corresponding JOSE key operation VERIFY. It is used to specify that a key is intended
     * for verifying cryptographic signatures.
     */
    object VERIFY : KeyOperations(CoseKeyOperations.VERIFY, JoseKeyOperations.VERIFY)

    /**
     * This object represents the key operation for decryption.
     * It maps the DECRYPT operation defined in both COSE and JOSE standards.
     */
    object DECRYPT : KeyOperations(CoseKeyOperations.DECRYPT, JoseKeyOperations.DECRYPT)

    /**
     * DERIVE_BITS is an object that maps the COSE key operation `DERIVE_BITS` to the equivalent JOSE key operation.
     * COSE (CBOR Object Signing and Encryption) and JOSE (JSON Object Signing and Encryption) are frameworks for object security,
     * and they define sets of operations that can be performed with keys.
     *
     * The `DERIVE_BITS` operation is used for deriving bits that are not intended to be used directly as a cryptographic key.
     * It requires private key fields to be present in the key object.
     *
     * This object is a specific instance of the `KeyOperationsMapping` class, which is used to map COSE key operations to JOSE key operations.
     * By providing this mapping, it's easier to ensure compatibility between the two frameworks.
     */
    object DERIVE_BITS : KeyOperations(CoseKeyOperations.DERIVE_BITS, JoseKeyOperations.DERIVE_BITS)

    /**
     * Provides an object for the ENCRYPT key operation in both COSE and JOSE contexts.
     *
     * This object enables the key to be used for key transport encryption as specified
     * in both COSE (CBOR Object Signing and Encryption) and JOSE (JSON Object Signing and Encryption).
     *
     * In COSE, the usage is defined by the `CoseKeyOperations.ENCRYPT` enumeration value.
     * In JOSE, the usage is defined by the `JoseKeyOperations.ENCRYPT` enumeration value.
     */
    object ENCRYPT : KeyOperations(CoseKeyOperations.ENCRYPT, JoseKeyOperations.ENCRYPT)

    /**
     * The `MAC_CREATE` object represents a mapping for the MAC creation operation in both COSE and JOSE contexts.
     *
     * This object is used for the creation of Message Authentication Codes (MACs).
     *
     * It maps the COSE key operation `CoseKeyOperations.MAC_CREATE` to the corresponding JOSE key operation `JoseKeyOperations.MAC_CREATE`.
     */
    object MAC_CREATE : KeyOperations(CoseKeyOperations.MAC_CREATE, JoseKeyOperations.MAC_CREATE)

    /**
     * Represents the MAC verification key operation.
     * Maps the COSE key operation "MAC verify" to the JOSE key operation "MAC verify".
     */
    object MAC_VERIFY : KeyOperations(CoseKeyOperations.MAC_VERIFY, JoseKeyOperations.MAC_VERIFY)

    /**
     * jose represents the set of operations defined under the JSON Web Key (JWK) standard.
     * These operations include actions such as signing, verifying, encrypting, decrypting,
     * wrapping keys, unwrapping keys, deriving keys, deriving bits, creating MACs, and
     * verifying MACs.
     */
    val jose = joseKeyOperations

    /**
     * An instance of [CoseKeyOperations] which specifies the operations
     * permitted to be performed using the key.
     */
    val cose = coseKeyOperations

    /**
     * An object that provides mappings between JOSE and COSE key operations.
     */
    companion object {
        /**
         * A list containing various key operations that can be performed.
         *
         * The available operations include:
         * - WRAP_KEY: Key wrap encryption.
         * - DERIVE_KEY: Deriving keys, requires private key fields.
         * - DERIVE_BITS: Deriving bits not used as a key, requires private key fields.
         * - UNWRAP_KEY: Key wrap decryption, requires private key fields.
         * - SIGN: Creating signatures, requires private key fields.
         * - VERIFY: Verification of signatures.
         * - DECRYPT: Key transport decryption.
         * - ENCRYPT: Key transport encryption.
         * - MAC_CREATE: Creating MACs.
         * - MAC_VERIFY: Validating MACs.
         *
         * This list is used to map between different key operation representations.
         */
        @JsStatic
        val asList: List<KeyOperations>
            get() =
                listOf(
                    WRAP_KEY,
                    DERIVE_KEY,
                    DERIVE_BITS,
                    UNWRAP_KEY,
                    SIGN,
                    VERIFY,
                    DECRYPT,
                    ENCRYPT,
                    MAC_CREATE,
                    MAC_VERIFY,
                )

        // Safe (non-throwing) variants - return IdkResult

        /**
         * Safely maps a JOSE key operation to its corresponding KeyOperations instance.
         * @return IdkResult containing the KeyOperations mapping, or an error if not found.
         */
        @JsStatic
        @JvmStatic
        fun tryFromJose(jose: JoseKeyOperations): IdkResult<KeyOperations, IdkError> =
            asList
                .find { it.joseKeyOperations == jose || it.joseKeyOperations.toString() == jose.toString() }
                ?.let { Ok(it) }
                ?: Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "JOSE key operation $jose not found"))

        /**
         * Safely converts a COSE key operation to its corresponding KeyOperations instance.
         * @return IdkResult containing the KeyOperations mapping, or an error if not found.
         */
        @JsStatic
        @JvmStatic
        fun tryFromCose(cose: CoseKeyOperations): IdkResult<KeyOperations, IdkError> =
            asList
                .find { it.coseKeyOperations == cose || it.coseKeyOperations.toString() == cose.toString() }
                ?.let { Ok(it) }
                ?: Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "COSE key operation $cose not found"))

        /**
         * Safely converts a COSE key operation to its equivalent JOSE key operation.
         * @return IdkResult containing the JOSE key operation, or an error if not found.
         */
        @JsStatic
        @JvmStatic
        fun tryToJose(cose: CoseKeyOperations): IdkResult<JoseKeyOperations, IdkError> =
            tryFromCose(cose).let { result ->
                when {
                    result.isOk -> Ok(result.value.joseKeyOperations)
                    else -> Err(result.error)
                }
            }

        /**
         * Safely converts a JOSE key operation to its corresponding COSE key operation.
         * @return IdkResult containing the COSE key operation, or an error if not found.
         */
        @JsStatic
        @JvmStatic
        fun tryToCose(jose: JoseKeyOperations): IdkResult<CoseKeyOperations, IdkError> =
            tryFromJose(jose).let { result ->
                when {
                    result.isOk -> Ok(result.value.coseKeyOperations)
                    else -> Err(result.error)
                }
            }

        /**
         * Safely parses a string value to the corresponding KeyOperations instance.
         * @return IdkResult containing the KeyOperations instance, or an error if not recognized.
         */
        @JsStatic
        @JvmStatic
        fun tryFromValue(value: String): IdkResult<KeyOperations, IdkError> =
            when (value) {
                "sign" -> Ok(SIGN)
                "verify" -> Ok(VERIFY)
                "wrapKey" -> Ok(WRAP_KEY)
                "decrypt" -> Ok(DECRYPT)
                "deriveBits" -> Ok(DERIVE_BITS)
                "deriveKey" -> Ok(DERIVE_KEY)
                "encrypt" -> Ok(ENCRYPT)
                "macCreate" -> Ok(MAC_CREATE)
                "macVerify" -> Ok(MAC_VERIFY)
                "unwrapKey" -> Ok(UNWRAP_KEY)
                else -> Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Unknown key operation value: $value"))
            }

        // Throwing variants - for backwards compatibility

        /**
         * Maps a `JoseKeyOperations` enum value to its corresponding `KeyOperationsMapping` instance.
         *
         * @param jose The `JoseKeyOperations` enum value to map.
         * @return The corresponding `KeyOperationsMapping` instance.
         * @throws IllegalArgumentException if the provided `JoseKeyOperations` value does not map to any `KeyOperationsMapping` instance.
         */
        @JsStatic
        @JvmStatic
        fun fromJose(jose: JoseKeyOperations) =
            tryFromJose(jose).getOrElse {
                throw IllegalArgumentException(it.message.defaultMessage)
            }

        /**
         * Converts a COSE key operation to its corresponding KeyOperation object.
         *
         * @param cose The COSE key operation to be converted.
         * @throws IllegalArgumentException if the provided COSE key operation is not found in the list.
         * @return The corresponding KeyOperation object.
         */
        @JsStatic
        @JvmStatic
        fun fromCose(cose: CoseKeyOperations) =
            tryFromCose(cose).getOrElse {
                throw IllegalArgumentException(it.message.defaultMessage)
            }

        /**
         * Converts a given COSE key operation to its equivalent JOSE key operation.
         *
         * @param cose The COSE key operation to be converted.
         * @throws IllegalArgumentException if the corresponding JOSE key operation is not found.
         * @return The equivalent JOSE key operation.
         */
        @JsStatic
        @JvmStatic
        fun toJose(cose: CoseKeyOperations) =
            tryToJose(cose).getOrElse {
                throw IllegalArgumentException(it.message.defaultMessage)
            }

        /**
         * Converts a given JOSE key operation to its corresponding COSE key operation.
         *
         * @param jose The JOSE key operation to be converted.
         * @return The corresponding COSE key operation.
         * @throws IllegalArgumentException if the specified JOSE key operation is not found.
         */
        @JsStatic
        @JvmStatic
        fun toCose(jose: JoseKeyOperations) =
            tryToCose(jose).getOrElse {
                throw IllegalArgumentException(it.message.defaultMessage)
            }

        @JsStatic
        @JvmStatic
        fun fromValue(value: String): KeyOperations =
            tryFromValue(value).getOrElse {
                throw IllegalArgumentException(it.message.defaultMessage)
            }

        @JsStatic
        @JvmStatic
        fun toValue(value: KeyOperations): String =
            when (value) {
                SIGN -> "sign"
                VERIFY -> "verify"
                WRAP_KEY -> "wrapKey"
                DECRYPT -> "decrypt"
                DERIVE_BITS -> "deriveBits"
                DERIVE_KEY -> "deriveKey"
                ENCRYPT -> "encrypt"
                MAC_CREATE -> "macCreate"
                MAC_VERIFY -> "macVerify"
                UNWRAP_KEY -> "unwrapKey"
            }
    }
}

/**
 * Converts a `CoseKeyOperations` enum to a corresponding `JoseKeyOperations` enum.
 *
 * This function utilizes a static mapping defined in the `KeyOperationsMapping` class
 * to transform the COSE key operation into a JOSE key operation.
 *
 * @receiver The `CoseKeyOperations` instance to be converted.
 * @return The corresponding `JoseKeyOperations` instance.
 * @throws IllegalArgumentException if the COSE key operation cannot be mapped to a JOSE key operation.
 */
@JsExportCompat
fun CoseKeyOperations.toJoseKeyOperations() = KeyOperations.toJose(this)

/**
 * Converts a `JoseKeyOperations` enum instance to its corresponding `CoseKeyOperations` enum instance.
 *
 * This method maps JOSE key operations like signing, verifying, encrypting,
 * decrypting, wrapping keys, unwrapping keys, deriving keys, deriving bits,
 * creating MACs, and verifying MACs to their COSE counterparts.
 *
 * @receiver the `JoseKeyOperations` instance to be converted.
 * @return the corresponding `CoseKeyOperations` instance.
 * @throws IllegalArgumentException if the JOSE key operation cannot be mapped to a COSE key operation.
 */
@JsExportCompat
fun JoseKeyOperations.toCoseKeyOperations() = KeyOperations.toCose(this)
