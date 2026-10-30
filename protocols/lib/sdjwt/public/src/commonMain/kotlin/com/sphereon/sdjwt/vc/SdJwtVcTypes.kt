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

import com.sphereon.core.compat.JsExportCompat
import com.sphereon.sdjwt.KeyBindingJwt
import com.sphereon.sdjwt.SdJwtCompact
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject

/*
 * SD-JWT-VC (Verifiable Credential) types and metadata
 * Based on draft-ietf-oauth-sd-jwt-vc-11, as referenced by OID4VCI 1.0 Final.
 *
 * SD-JWT-VC extends SD-JWT with:
 * - Verifiable Credential type metadata (vct)
 * - Issuer metadata resolution
 * - Type metadata resolution
 * - Status information
 * - Display metadata
 */

/**
 * Media types for SD-JWT-VC
 * As defined in draft-ietf-oauth-sd-jwt-vc-13 §4.1
 */
object SdJwtVcMediaTypes {
    /** W3C VCDM 2.0 credential secured using SD-JWT (VC JOSE/COSE). */
    const val W3C_VC_SD_JWT = "application/vc+sd-jwt"

    /** IETF SD-JWT VC media type; `dc` means digital credential. */
    const val IETF_SD_JWT_VC = "application/dc+sd-jwt"
}

/**
 * Type header values for SD-JWT-VC JWTs
 * As defined in draft-ietf-oauth-sd-jwt-vc-13 §4.1
 */
object SdJwtVcTypeHeaders {
    /** W3C VCDM 2.0 credential secured using SD-JWT (VC JOSE/COSE). */
    const val W3C_VC_SD_JWT = "vc+sd-jwt"

    /** IETF SD-JWT VC `typ` value. */
    const val IETF_SD_JWT_VC = "dc+sd-jwt"
}

/**
 * Issuer metadata for SD-JWT-VC
 * Retrieved from /.well-known/jwt-vc-issuer endpoint
 *
 * @property issuer Issuer identifier (REQUIRED)
 * @property jwksUri URL to issuer's JWK Set (OPTIONAL, mutually exclusive with jwks)
 * @property jwks Inline JWK Set (OPTIONAL, mutually exclusive with jwksUri)
 */
@Serializable
@JsExportCompat
data class SdJwtVcIssuerMetadata(
    @SerialName("issuer")
    val issuer: String,
    @SerialName("jwks_uri")
    val jwksUri: String? = null,
    @SerialName("jwks")
    val jwks: JsonObject? = null,
) {
    init {
        // Either jwks or jwksUri must be provided, but not both
        require((jwks != null) xor (jwksUri != null)) {
            "Either 'jwks' or 'jwks_uri' must be provided (mutually exclusive)"
        }
    }
}

/**
 * Type metadata for SD-JWT-VC (draft-ietf-oauth-sd-jwt-vc-11 format)
 * Describes the structure and properties of a credential type
 *
 * @property vct Verifiable Credential Type identifier (REQUIRED)
 * @property name Human-readable name (OPTIONAL)
 * @property description Human-readable description (OPTIONAL)
 * @property extends URL to parent type metadata (OPTIONAL)
 * @property extendsIntegrity Integrity protection for extends URL (OPTIONAL)
 * @property display Display information for different locales (OPTIONAL)
 * @property claims Information about credential claims (OPTIONAL)
 * @property schema Embedded JSON schema document (OPTIONAL)
 * @property schemaUri JSON schema URL (OPTIONAL)
 * @property schemaIntegrity Integrity protection for schema URL (OPTIONAL)
 */
@Serializable
@JsExportCompat
data class SdJwtVcTypeMetadata(
    @SerialName("vct")
    val vct: String,
    @SerialName("name")
    val name: String? = null,
    @SerialName("description")
    val description: String? = null,
    @SerialName("extends")
    val extends: String? = null,
    @SerialName("extends#integrity")
    val extendsIntegrity: String? = null,
    @SerialName("display")
    val display: List<DisplayInformation>? = null,
    @SerialName("claims")
    val claims: List<ClaimInformation>? = null,
    @SerialName("schema")
    val schema: JsonObject? = null,
    @SerialName("schema_uri")
    val schemaUri: String? = null,
    @SerialName("schema_uri#integrity")
    val schemaIntegrity: String? = null,
)

/**
 * Display information for credentials (localized)
 *
 * @property locale Language/locale code (e.g., "en-US", "fr-FR")
 * @property name Localized credential name
 * @property description Localized credential description (OPTIONAL)
 * @property rendering Rendering metadata (OPTIONAL)
 */
@Serializable
@JsExportCompat
data class DisplayInformation(
    @SerialName("locale")
    val locale: String,
    @SerialName("name")
    val name: String,
    @SerialName("description")
    val description: String? = null,
    @SerialName("rendering")
    val rendering: RenderingMetadata? = null,
)

/**
 * Rendering metadata for credential display
 *
 * @property simple Simple rendering method (colors, logos)
 * @property svgTemplates SVG template rendering methods
 */
@Serializable
@JsExportCompat
data class RenderingMetadata(
    @SerialName("simple")
    val simple: SimpleRenderingMethod? = null,
    @SerialName("svg_templates")
    val svgTemplates: List<SvgTemplateRenderingMethod>? = null,
)

/**
 * Simple rendering method with colors and images
 *
 * @property logo Logo metadata
 * @property backgroundImage Background image metadata
 * @property backgroundColor Background color (hex format)
 * @property textColor Text color (hex format)
 */
@Serializable
@JsExportCompat
data class SimpleRenderingMethod(
    @SerialName("logo")
    val logo: LogoMetadata? = null,
    @Transient
    val backgroundImage: BackgroundImageMetadata? = null,
    @SerialName("background_color")
    val backgroundColor: String? = null,
    @SerialName("text_color")
    val textColor: String? = null,
)

/**
 * SVG template rendering method
 *
 * @property uri URL to SVG template
 * @property uriIntegrity Integrity protection for SVG URL
 * @property properties SVG template properties
 */
@Serializable
@JsExportCompat
data class SvgTemplateRenderingMethod(
    @SerialName("uri")
    val uri: String,
    @SerialName("uri#integrity")
    val uriIntegrity: String? = null,
    @SerialName("properties")
    val properties: SvgTemplateProperties? = null,
)

/**
 * SVG template properties
 *
 * @property orientation Portrait or landscape
 * @property colorScheme Light or dark theme
 * @property contrast Normal or high contrast
 */
@Serializable
@JsExportCompat
data class SvgTemplateProperties(
    @SerialName("orientation")
    val orientation: SvgTemplateOrientation? = null,
    @SerialName("color_scheme")
    val colorScheme: SvgTemplateColorScheme? = null,
    @SerialName("contrast")
    val contrast: SvgTemplateContrast? = null,
)

@Serializable
@JsExportCompat
enum class SvgTemplateOrientation {
    @SerialName("portrait")
    PORTRAIT,

    @SerialName("landscape")
    LANDSCAPE,
}

@Serializable
@JsExportCompat
enum class SvgTemplateColorScheme {
    @SerialName("light")
    LIGHT,

    @SerialName("dark")
    DARK,
}

@Serializable
@JsExportCompat
enum class SvgTemplateContrast {
    @SerialName("normal")
    NORMAL,

    @SerialName("high")
    HIGH,
}

/**
 * Logo metadata
 *
 * @property uri URL to logo image
 * @property uriIntegrity Integrity protection for logo URL
 * @property altText Alternative text for accessibility
 */
@Serializable
@JsExportCompat
data class LogoMetadata(
    @SerialName("uri")
    val uri: String,
    @SerialName("uri#integrity")
    val uriIntegrity: String? = null,
    @SerialName("alt_text")
    val altText: String? = null,
)

/**
 * Background image metadata
 *
 * @property uri URL to background image
 * @property uriIntegrity Integrity protection for image URL
 */
@Serializable
@JsExportCompat
data class BackgroundImageMetadata(
    @SerialName("uri")
    val uri: String,
    @SerialName("uri#integrity")
    val uriIntegrity: String? = null,
)

/**
 * Information about a credential claim
 *
 * @property path JSON path to claim (may contain null for array indices per spec)
 * @property display Localized display information
 * @property mandatory Whether claim is mandatory
 * @property sd Selective disclosure metadata (always/allowed/never)
 * @property svgId SVG element ID for rendering
 */
@Serializable
@JsExportCompat
data class ClaimInformation(
    @SerialName("path")
    val path: List<String?>, // May contain null per spec for array indices
    @SerialName("display")
    val display: List<ClaimDisplayMetadata>? = null,
    @Transient
    val mandatory: Boolean = false,
    @SerialName("sd")
    val sd: ClaimSdMetadata = ClaimSdMetadata.ALLOWED,
    @SerialName("svg_id")
    val svgId: String? = null,
)

/**
 * Display metadata for a claim (localized)
 *
 * @property locale Language/locale code
 * @property label Localized claim label
 * @property description Localized claim description
 */
@Serializable
@JsExportCompat
data class ClaimDisplayMetadata(
    @SerialName("locale")
    val locale: String,
    @SerialName("label")
    val label: String,
    @SerialName("description")
    val description: String? = null,
)

/**
 * Selective disclosure metadata for claims
 */
@Serializable
@JsExportCompat
enum class ClaimSdMetadata {
    /** Claim MUST be selectively disclosable */
    @SerialName("always")
    ALWAYS,

    /** Claim MAY be selectively disclosable */
    @SerialName("allowed")
    ALLOWED,

    /** Claim MUST NOT be selectively disclosable */
    @SerialName("never")
    NEVER,
}

/**
 * Credential status information
 * Used for revocation and validity checking
 *
 * @property statusList Status list reference (OPTIONAL)
 * @property statusAssertion Status assertion (OPTIONAL)
 */
@Serializable
@JsExportCompat
data class CredentialStatus(
    @SerialName("status_list")
    val statusList: StatusListReference? = null,
    @SerialName("status_assertion")
    val statusAssertion: JsonElement? = null,
)

/**
 * Reference to a status list
 *
 * @property uri URL to status list
 * @property idx Index in status list
 */
@Serializable
@JsExportCompat
data class StatusListReference(
    @SerialName("uri")
    val uri: String,
    @SerialName("idx")
    val idx: Int,
)

/**
 * Result of type metadata resolution
 */
sealed interface TypeMetadataResolutionResult {
    /**
     * Successfully resolved metadata.
     *
     * @property rawDocument The exact octets the metadata was parsed from, which is the input an
     * `#integrity` expression covers. Null when the resolver has no original representation, in which
     * case an integrity pin cannot be verified.
     */
    class Success(
        val metadata: SdJwtVcTypeMetadata,
        rawDocument: ByteArray? = null,
    ) : TypeMetadataResolutionResult {
        private val raw: ByteArray? = rawDocument?.copyOf()

        /** A copy of the retrieved octets, so callers cannot alter retained evidence. */
        val rawDocument: ByteArray? get() = raw?.copyOf()

        fun copy(metadata: SdJwtVcTypeMetadata = this.metadata): Success = Success(metadata, raw)

        override fun equals(other: Any?): Boolean =
            other is Success && metadata == other.metadata && raw.contentEquals(other.raw)

        override fun hashCode(): Int = 31 * metadata.hashCode() + (raw?.contentHashCode() ?: 0)

        override fun toString(): String = "Success(metadata=$metadata, rawDocument=${raw?.size ?: 0} bytes)"
    }

    /** Failed to resolve metadata */
    data class Failure(
        val error: TypeMetadataResolutionError,
    ) : TypeMetadataResolutionResult
}

/**
 * Errors during type metadata resolution
 */
sealed interface TypeMetadataResolutionError {
    /** Network or fetch error */
    data class NetworkError(
        val message: String,
        val cause: Throwable? = null,
    ) : TypeMetadataResolutionError

    /** Invalid metadata format */
    data class InvalidFormat(
        val message: String,
    ) : TypeMetadataResolutionError

    /** Metadata not found */
    data object NotFound : TypeMetadataResolutionError

    /** Unsupported VCT format */
    data class UnsupportedVct(
        val vct: String,
    ) : TypeMetadataResolutionError

    /** Circular dependency detected in type extends chain (draft-13 §7.2.3) */
    data class CircularDependency(
        val vct: String,
        val chain: List<String>,
    ) : TypeMetadataResolutionError
}

/**
 * Result of issuer metadata resolution
 */
sealed interface IssuerMetadataResolutionResult {
    /** Successfully resolved metadata */
    data class Success(
        val metadata: SdJwtVcIssuerMetadata,
    ) : IssuerMetadataResolutionResult

    /** Failed to resolve metadata */
    data class Failure(
        val error: IssuerMetadataResolutionError,
    ) : IssuerMetadataResolutionResult
}

/**
 * Errors during issuer metadata resolution
 */
sealed interface IssuerMetadataResolutionError {
    /** Network or fetch error */
    data class NetworkError(
        val message: String,
        val cause: Throwable? = null,
    ) : IssuerMetadataResolutionError

    /** Invalid metadata format */
    data class InvalidFormat(
        val message: String,
    ) : IssuerMetadataResolutionError

    /** Metadata not found */
    data object NotFound : IssuerMetadataResolutionError

    /** Invalid issuer URL */
    data class InvalidIssuerUrl(
        val issuer: String,
    ) : IssuerMetadataResolutionError
}

// ============================================================================
// SD-JWT-VC Verification Types
// ============================================================================

/**
 * Options for SD-JWT-VC verification
 */
@JsExportCompat
data class SdJwtVcVerificationOpts(
    val validateTypeMetadata: Boolean = true,
    val validateStatus: Boolean = false,
    val typeMetadataResolver: TypeMetadataResolver? = null,
    val issuerMetadataResolver: IssuerMetadataResolver? = null,
)

/**
 * Result of SD-JWT-VC verification (without KB-JWT)
 *
 * @property sdJwt Verified SD-JWT
 * @property vct Verifiable Credential Type
 * @property typeMetadata Resolved type metadata (if validation enabled)
 * @property issuerMetadata Resolved issuer metadata
 */
@JsExportCompat
data class SdJwtVcVerificationResult(
    val sdJwt: SdJwtCompact,
    val vct: String,
    val typeMetadata: SdJwtVcTypeMetadata?,
    val issuerMetadata: SdJwtVcIssuerMetadata?,
)

/**
 * Result of SD-JWT-VC presentation verification (with KB-JWT)
 *
 * @property sdJwt Verified SD-JWT
 * @property kbJwt Verified Key Binding JWT
 * @property vct Verifiable Credential Type
 * @property typeMetadata Resolved type metadata (if validation enabled)
 * @property issuerMetadata Resolved issuer metadata
 */
@JsExportCompat
data class SdJwtVcPresentationVerificationResult(
    val sdJwt: SdJwtCompact,
    val kbJwt: KeyBindingJwt,
    val vct: String,
    val typeMetadata: SdJwtVcTypeMetadata?,
    val issuerMetadata: SdJwtVcIssuerMetadata?,
)
