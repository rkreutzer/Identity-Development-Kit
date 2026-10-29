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

package com.sphereon.openid.oid4vp.common

import com.sphereon.core.compat.JsExportCompat
import com.sphereon.core.compat.JsExportIgnoreCompat
import com.sphereon.crypto.core.jose.AlgorithmType
import com.sphereon.crypto.core.jose.JoseKeyOperations
import com.sphereon.crypto.core.jose.JwkSet
import com.sphereon.crypto.core.jose.JwkType
import io.konform.validation.Validation
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Client Metadata for OpenID4VP, per OpenID4VP 1.0 Final.
 *
 * Verified against the spec source at github.com/openid/OpenID4VP/blob/main/1.0/openid-4-verifiable-presentations-1_0.md.
 * The shape here is **deliberately narrow**: only the parameters OID4VP 1.0 final and
 * HAIP 1.0 explicitly define for the verifier's `client_metadata` request parameter.
 *
 * Authoritative parameter list:
 *  - **OID4VP §5.1** (`client_metadata` parameter description): `jwks`,
 *    `encrypted_response_enc_values_supported`.
 *  - **OID4VP §8.3** (Encrypted Responses): the JWE `alg` is read from the chosen
 *    `jwks` key's `alg` field — there is NO top-level `encrypted_response_alg_values_supported`
 *    in the spec. The JWE `enc` is selected from `encrypted_response_enc_values_supported`,
 *    defaulting to `A128GCM`.
 *  - **OID4VP §11.1** (Additional Verifier Metadata Parameters): adds `vp_formats_supported`
 *    (REQUIRED when not available out-of-band).
 *  - **HAIP §5** (Cryptographic Algorithms): "Verifiers MUST list both `A128GCM` and
 *    `A256GCM` in `encrypted_response_enc_values_supported`."
 *
 * What's NOT here (and why):
 *  - `authorization_encrypted_response_alg/enc` — JARM RFC terms, NOT defined by
 *    OID4VP 1.0 final. `alg` lives on the JWK; OIDF conformance flags these as unknown.
 *  - `encrypted_response_alg_values_supported` (the plural alg list) — also not spec; the
 *    wallet derives the alg from the JWK.
 *  - `client_purpose` — not defined by OID4VP 1.0 final §11.1 (was a draft-era field).
 *  - OAuth2 RFC 7591 client-registration fields (`client_id`, `grant_types`, `redirect_uris`,
 *    `client_type`, `token_endpoint_auth_method`, …) — OID4VP §11.1 says additional fields
 *    "MAY be defined per RFC 7591" but the wallet "MUST ignore any unrecognized parameters",
 *    so emitting OAuth2 reg fields is non-canonical noise. Model OAuth2 registration
 *    separately if needed.
 */
@Serializable
@JsExportCompat
data class ClientMetadata(
    /**
     * Verifier's JSON Web Key Set (RFC 7517). For `direct_post.jwt` (encrypted responses)
     * MUST contain the encryption public key per OID4VP §8.3 — wallet picks one and the
     * JWE `alg` equals the chosen JWK's `alg`. Per HAIP §5 the JWK MUST be ECDH-ES P-256.
     */
    @Serializable(with = ClientMetadataJwkSetSerializer::class)
    val jwks: JwkSet? = null,
    @SerialName("jwks_uri")
    val jwksUri: String? = null,
    /**
     * Credential formats + per-format algorithm lists the verifier supports.
     * REQUIRED when not available to the Wallet via another mechanism (OID4VP §11.1).
     */
    @JsExportIgnoreCompat
    @SerialName("vp_formats_supported")
    val vpFormatsSupported: Map<String, VpFormatInfo>? = null,
    /**
     * JWE `enc` values the verifier accepts for the encrypted authorization response
     * (OID4VP §5.1 / §8.3). HAIP §5 mandates `A128GCM` and `A256GCM` minimum. Default
     * when omitted is `A128GCM`.
     */
    @SerialName("encrypted_response_enc_values_supported")
    val encryptedResponseEncValuesSupported: List<String>? = null,
)

/**
 * Selects the verifier key used for an encrypted OID4VP authorization response.
 *
 * The selected key drives regular OID4VP JWE encryption. The ISO 18013-7 Annex B
 * adapter reuses this key-selection primitive for its `kid` binding, while keeping
 * the ISO handover and metadata validation in the ISO-specific transport.
 */
fun ClientMetadata.selectEncryptedResponseJwk(requireAlgorithm: Boolean = true): JwkType? =
    jwks?.keys?.firstOrNull { jwk ->
        val hasEncryptionOperation =
            jwk.key_ops?.any { operation ->
                operation == JoseKeyOperations.ENCRYPT || operation == JoseKeyOperations.WRAP_KEY
            } == true
        val hasContradictoryUse = jwk.use != null && jwk.use != "enc"
        val hasContradictoryOperations = jwk.key_ops != null && !hasEncryptionOperation
        val hasExplicitEncryptionIntent = jwk.use == "enc" || hasEncryptionOperation
        val hasEncryptionAlgorithm = jwk.alg?.type == AlgorithmType.ENCRYPTION
        // RFC 7517 makes `use` optional. OID4VP §8.3 requires `alg` on the JWK
        // and binds the JWE alg to it, so an encryption alg can identify an
        // encryption key when neither optional `use` nor `key_ops` is present.
        // Any explicit contradictory intent remains disqualifying.
        val isEncryptionKey =
            !hasContradictoryUse && !hasContradictoryOperations &&
                (hasExplicitEncryptionIntent || (jwk.use == null && jwk.key_ops == null && hasEncryptionAlgorithm))
        isEncryptionKey && (hasEncryptionAlgorithm || (!requireAlgorithm && jwk.alg == null))
    }

/**
 * VP Format Information (vp_formats_supported)
 *
 * Per OpenID4VP 1.0 Final Section 9.1, describes the VP formats and algorithms
 * supported by a verifier (client). This is used in client_metadata to indicate
 * which credential formats the verifier can accept.
 *
 * Different credential formats have different algorithm fields:
 * - **dc+sd-jwt** / **vc+sd-jwt**: Uses `sd-jwt_alg_values` and `kb-jwt_alg_values`
 * - **mso_mdoc**: Uses `issuerauth_alg_values` and `deviceauth_alg_values` (COSE algorithm numbers)
 * - **jwt_vc_json**: Uses `alg_values` (JWS algorithms)
 * - **ldp_vc**: Uses `proof_type_values` and `cryptosuite_values` (Data Integrity)
 *
 * Reference: OpenID4VP 1.0 Final Section 9.1
 *
 * @property sdJwtAlgValuesSupported JWS algorithms for SD-JWT issuer signature (dc+sd-jwt, vc+sd-jwt)
 * @property kbJwtAlgValuesSupported JWS algorithms for Key Binding JWT (dc+sd-jwt, vc+sd-jwt)
 * @property algValuesSupported General JWS algorithms (jwt_vc_json)
 * @property proofTypeValues Data Integrity proof type identifiers (ldp_vc)
 * @property cryptosuiteValues Data Integrity cryptosuite identifiers (ldp_vc)
 * @property issuerAuthAlgValuesSupported COSE algorithms for IssuerAuth in mdoc (mso_mdoc)
 * @property deviceAuthAlgValuesSupported COSE algorithms for DeviceAuth in mdoc (mso_mdoc)
 */
@Serializable
@JsExportCompat
data class VpFormatInfo(
    /**
     * JWS algorithms supported for SD-JWT issuer signature.
     * Applicable to "dc+sd-jwt" and "vc+sd-jwt" formats.
     * Example: ["ES256", "ES384", "ES512"]
     */
    @SerialName("sd-jwt_alg_values")
    val sdJwtAlgValuesSupported: List<String>? = null,
    /**
     * JWS algorithms supported for Key Binding JWT.
     * Applicable to "dc+sd-jwt" and "vc+sd-jwt" formats.
     * Example: ["ES256", "ES384"]
     */
    @SerialName("kb-jwt_alg_values")
    val kbJwtAlgValuesSupported: List<String>? = null,
    /**
     * General JWS algorithms supported.
     * Applicable to "jwt_vc_json" and similar JWT formats.
     * Example: ["ES256", "ES384", "RS256"]
     */
    @SerialName("alg_values")
    val algValuesSupported: List<String>? = null,
    /**
     * Data Integrity proof type identifiers supported for `ldp_vc`.
     * Example: ["DataIntegrityProof"]
     */
    @SerialName("proof_type_values")
    val proofTypeValues: List<String>? = null,
    /**
     * Data Integrity cryptosuite identifiers supported for `ldp_vc`.
     * Example: ["eddsa-rdfc-2022", "ecdsa-rdfc-2019"]
     */
    @SerialName("cryptosuite_values")
    val cryptosuiteValues: List<String>? = null,
    /**
     * COSE algorithms supported for IssuerAuth in mdoc.
     * Values are COSE algorithm numbers (e.g., -7 for ES256, -35 for ES384, -36 for ES512).
     * Applicable to "mso_mdoc" format.
     */
    @SerialName("issuerauth_alg_values")
    val issuerAuthAlgValuesSupported: List<Int>? = null,
    /**
     * COSE algorithms supported for DeviceAuth in mdoc.
     * Values are COSE algorithm numbers (e.g., -7 for ES256, -35 for ES384, -36 for ES512).
     * Applicable to "mso_mdoc" format.
     */
    @SerialName("deviceauth_alg_values")
    val deviceAuthAlgValuesSupported: List<Int>? = null,
)

/**
 * Konform validator for VpFormatInfo
 *
 * Validates that at least one algorithm specification is provided and
 * that algorithm identifiers follow expected formats.
 */
val validateVpFormatInfo =
    Validation<VpFormatInfo> {
        // At least one algorithm type must be specified
        constrain("At least one algorithm specification is required") {
            !it.sdJwtAlgValuesSupported.isNullOrEmpty() ||
                !it.kbJwtAlgValuesSupported.isNullOrEmpty() ||
                !it.algValuesSupported.isNullOrEmpty() ||
                !it.proofTypeValues.isNullOrEmpty() ||
                !it.cryptosuiteValues.isNullOrEmpty() ||
                !it.issuerAuthAlgValuesSupported.isNullOrEmpty() ||
                !it.deviceAuthAlgValuesSupported.isNullOrEmpty()
        }

        // Validate JWS algorithm formats (should be uppercase alphanumeric with hyphens)
        constrain("sd-jwt_alg_values must contain valid JWS algorithm identifiers") {
            it.sdJwtAlgValuesSupported?.all { alg -> alg.matches("[A-Z][A-Z0-9-]*".toRegex()) } ?: true
        }

        constrain("kb-jwt_alg_values must contain valid JWS algorithm identifiers") {
            it.kbJwtAlgValuesSupported?.all { alg -> alg.matches("[A-Z][A-Z0-9-]*".toRegex()) } ?: true
        }

        constrain("alg_values must contain valid JWS algorithm identifiers") {
            it.algValuesSupported?.all { alg -> alg.matches("[A-Z][A-Z0-9-]*".toRegex()) } ?: true
        }

        // Validate lists are not empty if present
        constrain("sd-jwt_alg_values must not be empty if specified") {
            it.sdJwtAlgValuesSupported?.isNotEmpty() ?: true
        }

        constrain("kb-jwt_alg_values must not be empty if specified") {
            it.kbJwtAlgValuesSupported?.isNotEmpty() ?: true
        }

        constrain("alg_values must not be empty if specified") {
            it.algValuesSupported?.isNotEmpty() ?: true
        }

        constrain("proof_type_values must not be empty if specified") {
            it.proofTypeValues?.isNotEmpty() ?: true
        }

        constrain("cryptosuite_values must not be empty if specified") {
            it.cryptosuiteValues?.isNotEmpty() ?: true
        }

        constrain("proof_type_values must contain non-blank identifiers") {
            it.proofTypeValues?.all(String::isNotBlank) ?: true
        }

        constrain("cryptosuite_values must contain non-blank identifiers") {
            it.cryptosuiteValues?.all(String::isNotBlank) ?: true
        }

        constrain("issuerauth_alg_values must not be empty if specified") {
            it.issuerAuthAlgValuesSupported?.isNotEmpty() ?: true
        }

        constrain("deviceauth_alg_values must not be empty if specified") {
            it.deviceAuthAlgValuesSupported?.isNotEmpty() ?: true
        }
    }

/**
 * Konform validator for [ClientMetadata] — checks the OID4VP §11.1 / HAIP §5 invariants.
 */
val validateClientMetadata =
    Validation<ClientMetadata> {
        // OID4VP §11.1: vp_formats_supported, when present, must hold at least one
        // valid format entry. (REQUIRED when no out-of-band mechanism — that gating
        // is a per-deployment concern, not enforced here.)
        ClientMetadata::vpFormatsSupported ifPresent {
            run {
                constrain("vp_formats_supported must contain at least one format") {
                    it.isNotEmpty()
                }
                constrain("All VP format entries must be valid") { formats ->
                    formats.values.all { formatInfo ->
                        validateVpFormatInfo(formatInfo).isValid
                    }
                }
            }
        }

        // HAIP §5: when emitted, encrypted_response_enc_values_supported MUST list both
        // A128GCM and A256GCM. We only enforce non-empty here since pure OID4VP (non-HAIP)
        // deployments may legitimately advertise a different set; HAIP-specific validation
        // belongs in a HAIP-profile validator if/when one is introduced.
        ClientMetadata::encryptedResponseEncValuesSupported ifPresent {
            constrain("encrypted_response_enc_values_supported must not be empty when present") {
                it.isNotEmpty()
            }
        }
    }

// =============================================================================
// Builder DSL for VpFormatInfo
// =============================================================================

/**
 * Builder for creating VpFormatInfo instances.
 *
 * Provides a convenient DSL for configuring VP format algorithm support.
 */
@JsExportCompat
class VpFormatInfoBuilder {
    private var sdJwtAlgValues: MutableList<String>? = null
    private var kbJwtAlgValues: MutableList<String>? = null
    private var algValues: MutableList<String>? = null
    private var proofTypeValues: MutableList<String>? = null
    private var cryptosuiteValues: MutableList<String>? = null
    private var issuerAuthAlgValues: MutableList<Int>? = null
    private var deviceAuthAlgValues: MutableList<Int>? = null

    /**
     * Set SD-JWT signing algorithms.
     */
    fun sdJwtAlgValues(vararg algs: String) =
        apply {
            sdJwtAlgValues = algs.toMutableList()
        }

    /**
     * Set Key Binding JWT algorithms.
     */
    fun kbJwtAlgValues(vararg algs: String) =
        apply {
            kbJwtAlgValues = algs.toMutableList()
        }

    /**
     * Set general JWS algorithms.
     */
    fun algValues(vararg algs: String) =
        apply {
            algValues = algs.toMutableList()
        }

    /**
     * Set Data Integrity proof type identifiers for `ldp_vc`.
     */
    fun proofTypeValues(vararg types: String) =
        apply {
            proofTypeValues = types.toMutableList()
        }

    /**
     * Set Data Integrity cryptosuite identifiers for `ldp_vc`.
     */
    fun cryptosuiteValues(vararg cryptosuites: String) =
        apply {
            cryptosuiteValues = cryptosuites.toMutableList()
        }

    /**
     * Set COSE algorithms for mdoc IssuerAuth.
     */
    fun issuerAuthAlgValues(vararg algs: Int) =
        apply {
            issuerAuthAlgValues = algs.toMutableList()
        }

    /**
     * Set COSE algorithms for mdoc DeviceAuth.
     */
    fun deviceAuthAlgValues(vararg algs: Int) =
        apply {
            deviceAuthAlgValues = algs.toMutableList()
        }

    fun build(): VpFormatInfo =
        VpFormatInfo(
            sdJwtAlgValuesSupported = sdJwtAlgValues?.toList(),
            kbJwtAlgValuesSupported = kbJwtAlgValues?.toList(),
            algValuesSupported = algValues?.toList(),
            proofTypeValues = proofTypeValues?.toList(),
            cryptosuiteValues = cryptosuiteValues?.toList(),
            issuerAuthAlgValuesSupported = issuerAuthAlgValues?.toList(),
            deviceAuthAlgValuesSupported = deviceAuthAlgValues?.toList(),
        )
}

/**
 * Create VpFormatInfo using a builder DSL.
 */
fun buildVpFormatInfo(block: VpFormatInfoBuilder.() -> Unit): VpFormatInfo = VpFormatInfoBuilder().apply(block).build()

// =============================================================================
// Convenience factory functions for common VP format configurations
// =============================================================================

/**
 * Create VP format metadata for an SD-JWT based representation.
 *
 * @param sdJwtAlgValues JWS algorithms for SD-JWT issuer signature (default: ES256, ES384)
 * @param kbJwtAlgValues JWS algorithms for Key Binding JWT (default: ES256, ES384)
 */
fun sdJwtVpFormatInfo(
    sdJwtAlgValues: List<String> = listOf("ES256", "ES384"),
    kbJwtAlgValues: List<String> = listOf("ES256", "ES384"),
): VpFormatInfo =
    VpFormatInfo(
        sdJwtAlgValuesSupported = sdJwtAlgValues,
        kbJwtAlgValuesSupported = kbJwtAlgValues,
    )

/**
 * Create VpFormatInfo for mso_mdoc format.
 *
 * @param issuerAuthAlgValues COSE algorithms for IssuerAuth (default: -7 (ES256), -35 (ES384), -36 (ES512))
 * @param deviceAuthAlgValues COSE algorithms for DeviceAuth (default: -7 (ES256), -35 (ES384), -36 (ES512))
 */
internal const val COSE_ALG_ES256 = -7
internal const val COSE_ALG_ES384 = -35
internal const val COSE_ALG_ES512 = -36
internal val DEFAULT_COSE_ALG_VALUES = listOf(COSE_ALG_ES256, COSE_ALG_ES384, COSE_ALG_ES512)

fun mdocVpFormatInfo(
    issuerAuthAlgValues: List<Int> = DEFAULT_COSE_ALG_VALUES,
    deviceAuthAlgValues: List<Int> = DEFAULT_COSE_ALG_VALUES,
): VpFormatInfo =
    VpFormatInfo(
        issuerAuthAlgValuesSupported = issuerAuthAlgValues,
        deviceAuthAlgValuesSupported = deviceAuthAlgValues,
    )

/**
 * Create VpFormatInfo for the JWT-secured W3C credential/presentation format (`jwt_vc_json`).
 *
 * @param algValues JWS algorithms supported (default: ES256, ES384, RS256)
 */
fun jwtVcFormatInfo(algValues: List<String> = listOf("ES256", "ES384", "RS256")): VpFormatInfo =
    VpFormatInfo(
        algValuesSupported = algValues,
    )

/**
 * Create VpFormatInfo for the W3C Data Integrity format (`ldp_vc`).
 *
 * @param proofTypeValues Data Integrity proof type identifiers supported
 * @param cryptosuiteValues Data Integrity cryptosuite identifiers supported
 */
fun ldpVcFormatInfo(
    proofTypeValues: List<String> = listOf("DataIntegrityProof"),
    cryptosuiteValues: List<String>? = null,
): VpFormatInfo =
    VpFormatInfo(
        proofTypeValues = proofTypeValues,
        cryptosuiteValues = cryptosuiteValues,
    )

// =============================================================================
// Builder DSL for ClientMetadata VP formats
// =============================================================================

/**
 * Builder for VP formats map in ClientMetadata.
 *
 * Provides a convenient DSL for configuring which VP formats a verifier supports.
 */
@JsExportCompat
class VpFormatsBuilder {
    private val formats = mutableMapOf<String, VpFormatInfo>()

    /**
     * Add support for IETF SD-JWT VC (`dc+sd-jwt`).
     */
    fun sdJwtVc(
        sdJwtAlgValues: List<String> = listOf("ES256", "ES384"),
        kbJwtAlgValues: List<String> = listOf("ES256", "ES384"),
    ) = apply {
        formats["dc+sd-jwt"] = sdJwtVpFormatInfo(sdJwtAlgValues, kbJwtAlgValues)
    }

    /**
     * Add support for a W3C VCDM credential secured using SD-JWT (`vc+sd-jwt`).
     */
    fun w3cVcSdJwt(
        sdJwtAlgValues: List<String> = listOf("ES256", "ES384"),
        kbJwtAlgValues: List<String> = listOf("ES256", "ES384"),
    ) = apply {
        formats["vc+sd-jwt"] = sdJwtVpFormatInfo(sdJwtAlgValues, kbJwtAlgValues)
    }

    /**
     * Add support for mso_mdoc format.
     */
    fun msoMdoc(
        issuerAuthAlgValues: List<Int> = DEFAULT_COSE_ALG_VALUES,
        deviceAuthAlgValues: List<Int> = DEFAULT_COSE_ALG_VALUES,
    ) = apply {
        formats["mso_mdoc"] = mdocVpFormatInfo(issuerAuthAlgValues, deviceAuthAlgValues)
    }

    /**
     * Add support for jwt_vc_json format.
     */
    fun jwtVcJson(algValues: List<String> = listOf("ES256", "ES384", "RS256")) =
        apply {
            formats["jwt_vc_json"] = jwtVcFormatInfo(algValues)
        }

    /**
     * Add support for ldp_vc format.
     */
    fun ldpVc(
        proofTypeValues: List<String> = listOf("DataIntegrityProof"),
        cryptosuiteValues: List<String>? = null,
    ) =
        apply {
            formats["ldp_vc"] = ldpVcFormatInfo(proofTypeValues, cryptosuiteValues)
        }

    /**
     * Add support for a custom format.
     */
    fun format(
        name: String,
        info: VpFormatInfo,
    ) = apply {
        formats[name] = info
    }

    /**
     * Add support for a custom format using a builder DSL.
     */
    @JsExportIgnoreCompat
    fun format(
        name: String,
        block: VpFormatInfoBuilder.() -> Unit,
    ) = apply {
        formats[name] = buildVpFormatInfo(block)
    }

    @JsExportIgnoreCompat
    fun build(): Map<String, VpFormatInfo> = formats.toMap()
}

/**
 * Create a VP formats map using a builder DSL.
 *
 * Example:
 * ```kotlin
 * val vpFormats = buildVpFormats {
 *     sdJwtVc()
 *     msoMdoc()
 *     jwtVcJson(listOf("ES256"))
 * }
 * ```
 */
fun buildVpFormats(block: VpFormatsBuilder.() -> Unit): Map<String, VpFormatInfo> = VpFormatsBuilder().apply(block).build()
