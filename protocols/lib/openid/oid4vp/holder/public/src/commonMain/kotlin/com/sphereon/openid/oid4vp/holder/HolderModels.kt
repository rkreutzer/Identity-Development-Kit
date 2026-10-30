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

package com.sphereon.openid.oid4vp.holder

import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.mdoc.PreparedMdocDeviceAuthenticationSigning
import com.sphereon.core.compat.JsExportCompat
import com.sphereon.core.compat.JsExportIgnoreCompat
import com.sphereon.oauth2.common.model.AuthorizationRequest
import com.sphereon.oauth2.common.model.AuthorizationErrorResponse
import com.sphereon.openid.oid4vc.common.CredentialFormat
import com.sphereon.openid.oid4vc.common.PresentationFormat
import com.sphereon.openid.oid4vp.common.ClientIdScheme
import com.sphereon.openid.oid4vp.common.ClientIdValidationError
import com.sphereon.openid.oid4vp.common.ClientMetadata
import com.sphereon.openid.oid4vp.common.ParsedTransactionDataEntry
import com.sphereon.openid.oid4vp.common.VerifierAttestation
import com.sphereon.openid.oid4vp.dcql.DcqlQuery
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject

/**
 * Authorization request delivered by the W3C Digital Credentials API.
 *
 * [origin] is trusted browser transport context. It is deliberately separate from [data]:
 * wallets must derive the web-origin client identity from the caller and must never accept an
 * `origin:` client identifier supplied by request JSON.
 */
@Serializable
@JsExportCompat
data class DigitalCredentialsAuthorizationRequest(
    val protocol: String,
    val data: JsonObject,
    val origin: String,
)

/**
 * Resolved OID4VP authorization request with all metadata and validation complete.
 *
 * This is the result of resolving an authorization request, which includes:
 * - Original request parameters
 * - Parsed DCQL query (if present)
 * - Client metadata (fetched or embedded)
 * - Verified client identity information
 * - Parsed transaction data (if present)
 * - Parsed verifier attestations (if present)
 *
 * Reference: OpenID4VP 1.0 Section 5
 *
 * @property request Original authorization request
 * @property dcqlQuery Parsed DCQL query (null if presentation_definition used)
 * @property clientMetadata Client metadata for the verifier
 * @property verifierInfo Information about the verified client identity
 * @property transactionData Parsed transaction data entries (per OpenID4VP 1.0 Section 5.1.2)
 * @property verifierAttestations Parsed verifier attestations from the verifier_info parameter (per OpenID4VP 1.0 Section 5.1.1)
 */
@Serializable
@JsExportCompat
data class ResolvedOid4vpRequest(
    val request: AuthorizationRequest,
    val dcqlQuery: DcqlQuery? = null,
    val clientMetadata: ClientMetadata? = null,
    val verifierInfo: VerifierInfo,
    val transactionData: List<ParsedTransactionDataEntry>? = null,
    val verifierAttestations: List<VerifierAttestation>? = null,
    /** Protocol error retained after client authentication, before any credential disclosure. */
    val authorizationError: AuthorizationErrorResponse? = null,
)

/**
 * Information about a verified client (verifier) identity.
 *
 * Client identity is established based on client_id_scheme:
 * - `pre-registered`: Client ID from pre-registration
 * - `redirect_uri`: Client ID matches redirect URI
 * - `entity_id`: Client ID is an Entity ID (OpenID Federation)
 * - `did`: Client ID is a DID
 * - `x509_san_dns`: Client ID from X.509 certificate SAN
 * - `x509_san_uri`: Client ID from X.509 certificate SAN URI
 * - `verifier_attestation`: Client verified via attestation JWT
 *
 * Reference: OpenID4VP 1.0 Section 10 - Client Identifier Schemes
 *
 * @property clientId The verified client identifier
 * @property clientIdScheme The scheme used to verify the client
 * @property clientIdValid Whether the client_id was validated according to its scheme
 * @property clientIdValidationErrors Validation errors if client_id validation failed
 * @property displayName Optional display name for the verifier
 * @property logoUri Optional logo URI for the verifier
 * @property trustRoot Optional trust root (for federation/PKI schemes)
 * @property requestObjectCertificateChain The `x5c` certificate chain (base64 DER, leaf first) that signed the
 *   Request Object, present only when the client_id was validated against an X.509 client identifier scheme
 */
@Serializable
@JsExportCompat
data class VerifierInfo(
    val clientId: String,
    val clientIdScheme: ClientIdScheme,
    val clientIdValid: Boolean = true,
    val clientIdValidationErrors: List<ClientIdValidationError> = emptyList(),
    val displayName: String? = null,
    val logoUri: String? = null,
    val trustRoot: String? = null,
    val requestObjectCertificateChain: List<String> = emptyList(),
)

/** Explicit result artifact prepared by the holder signing surface. */
@Serializable
@JsExportCompat
data class PreparedPresentation(
    /** The already holder-secured presentation to place on the OID4VP wire. */
    val presentation: JsonObject,
    /** Format of the already secured presentation artifact. */
    val presentationFormat: PresentationFormat,
    /** DCQL query IDs satisfied by this presentation. */
    val credentialQueryIds: List<String>,
    /** Wallet credential IDs included in this presentation. */
    val credentialIds: List<String>,
)

/**
 * A credential selected by the holder to include in the authorization response.
 *
 * Each selected credential must include:
 * - Credential query ID (from DCQL query)
 * - Identifier (local wallet ID)
 * - Credential format of the stored credential
 * - Presentation payload (signed/serialized credential)
 * - Optional disclosed claims (for selective disclosure formats)
 *
 * Reference: OpenID4VP 1.0 Section 6.1 - VP Token (DCQL Format)
 *
 * @property credentialQueryId The credential query ID from the DCQL query this presentation satisfies.
 *                             This is used as the key in the vp_token object.
 * @property credentialId Local identifier for the credential (wallet-specific)
 * @property presentation Credential/presentation wire value. Compact JWT, SD-JWT, and mdoc
 *                        values are JSON strings; Data Integrity credentials and presentations
 *                        are JSON objects. Keeping the protocol value as JSON preserves that
 *                        distinction without stringifying JSON-LD.
 * @property credentialFormat Credential format identifier of the stored credential. A VP format
 *                              is never accepted here; a produced VP is represented by
 *                              [PreparedPresentation.presentationFormat] or by the holder result.
 * @property disclosedClaims Optional map of disclosed claims (for SD-JWT)
 * @property holderKeyRef Opaque WSCA/WSCD reference for the holder key bound to this credential.
 *                        The holder signing surface resolves it; the protocol model does not select
 *                          a KMS or transport. When present for an SD-JWT format, the OID4VP holder
 *                          produces a Key Binding JWT (RFC 9901 Section 4.3) over the presentation,
 *                          binding it to the verifier's `client_id` (audience) and request `nonce`.
 *                          The stored [presentation] is the issuer SD-JWT; the holder appends the
 *                          freshly signed KB-JWT before submission.
 * @property sdJwtKeyBindingApplied True only when [presentation] is already a selectively disclosed
 *                                  SD-JWT presentation with its fresh KB-JWT applied by the holder's
 *                                  signing delegate. The holder validates the embedded KB-JWT request
 *                                  binding and submits that prepared artifact without signing it again.
 * @property holderId The holder identifier to place in a VCDM Verifiable Presentation. This is
 *                    deliberately separate from both the credential subject and [holderKeyRef]:
 *                    a holder key reference is key lookup metadata, and a presentation holder is
 *                    not inferred from the credentialSubject.
 * @property holderVerificationMethod Absolute controlled-identifier URL placed in a Data
 *                                    Integrity proof. It may resolve through DID, HTTPS/JWKS,
 *                                    X.509-backed, or another configured identifier resolver;
 *                                    it is never inferred from the private key alias.
 * @property dataIntegrityCryptosuite Cryptosuite used for a holder Data Integrity proof.
 */
@Serializable
@JsExportCompat
data class SelectedCredential(
    val credentialQueryId: String,
    val credentialId: String,
    val presentation: JsonElement,
    val credentialFormat: CredentialFormat,
    @JsExportIgnoreCompat
    val disclosedClaims: Map<String, String>? = null,
    val holderKeyRef: String? = null,
    val sdJwtKeyBindingApplied: Boolean = false,
    val holderId: String? = null,
    val holderVerificationMethod: String? = null,
    /**
     * Exact identifier source admitted for JWT VP signing. This runtime-only value keeps DID,
     * JWKS/managed kid, and X.509 selection explicit instead of inferring trust semantics from a
     * private key alias or from the spelling of [holderVerificationMethod].
     */
    @Transient
    @JsExportIgnoreCompat
    val holderJwtVpSigningIdentifier: HolderJwtVpSigningIdentifier? = null,
    /** Exact WSCA key algorithm supplied by wallet key metadata, never inferred from an identifier. */
    @Transient
    @JsExportIgnoreCompat
    val holderSigningAlgorithm: SignatureAlgorithm? = null,
    val dataIntegrityCryptosuite: String? = null,
    /** True only when a wallet WSCA binding provider already secured [presentation] as a VP. */
    val dataIntegrityProofApplied: Boolean = false,
    /** Attended wallet operation binding to carry into a WSCA-backed JWT VP signing provider. */
    val holderJwtVpOperationBinding: String? = null,
    /** Wallet unit owning [holderKeyRef]; never inferred from a key alias or tenant fallback. */
    val holderJwtVpWalletUnitId: String? = null,
)

/**
 * Prepared OpenID4VP encrypted-response recipient bound to mdoc DeviceAuthentication.
 * The JSON contains only the public JWK; its RFC 7638 thumbprint is also embedded
 * in the prepared DeviceAuthentication transcript and checked again before JWE creation.
 */
@Serializable
@JsExportCompat
data class PreparedOid4vpJweRecipientBinding(
    val publicJwkJson: String,
    val rfc7638Thumbprint: String,
    val keyEncryptionAlgorithm: String,
    val contentEncryptionAlgorithm: String,
    val responseMode: String,
    val clientId: String,
    val authorizationRequestNonce: String,
    val responseUri: String? = null,
    val redirectUri: String? = null,
    val callerOrigin: String? = null,
)

/** Prepared mdoc DeviceAuth signing operation bound to one selected credential and query. */
@Serializable
@JsExportCompat
data class PreparedMdocCredentialSigning(
    val credentialId: String,
    val credentialQueryId: String,
    val docType: String,
    val keyReference: String,
    val signing: PreparedMdocDeviceAuthenticationSigning,
    val recipientBinding: PreparedOid4vpJweRecipientBinding? = null,
)

/** Raw COSE signature returned by the context-bound signer for one prepared mdoc credential. */
@Serializable
@JsExportCompat
data class MdocCredentialSigningSignature(
    val credentialId: String,
    val signature: ByteArray,
)

/**
 * Result of submitting an authorization response to the verifier.
 *
 * Submission results vary by response_mode:
 * - `direct_post`: HTTP response from verifier
 * - `fragment`/`query`: Redirect URI (success assumed)
 *
 * Reference: OpenID4VP 1.0 Section 8.3 - Response Mode: direct_post
 *
 * @see SubmissionResult.Success
 * @see SubmissionResult.Error
 * @see SubmissionResult.Redirect
 */
sealed interface SubmissionResult {
    /**
     * Authorization-response data that must be returned through the W3C Digital Credentials API.
     * Transport wrapping (`protocol` plus this `data`) belongs to the wallet edge that received
     * the browser request; the holder service never invents that protocol identifier.
     */
    @Serializable
    data class DigitalCredential(
        val data: JsonObject,
    ) : SubmissionResult

    /**
     * Successful submission with verifier acknowledgment.
     *
     * @property redirectUri Optional redirect URI from verifier (for direct_post)
     * @property responseBody Optional response body from verifier
     */
    @Serializable
    data class Success(
        val redirectUri: String? = null,
        val responseBody: JsonObject? = null,
    ) : SubmissionResult

    /**
     * Submission failed with error.
     *
     * Reference: OpenID4VP 1.0 Section 8.3.2 - Error Response
     *
     * @property error Error code (e.g., "invalid_request", "invalid_client")
     * @property errorDescription Human-readable error description
     */
    @Serializable
    data class Error(
        val error: String,
        val errorDescription: String? = null,
    ) : SubmissionResult

    /**
     * Redirect-based submission (fragment or query mode).
     *
     * For redirect modes, the response is embedded in the redirect URI.
     * The holder should redirect the user to this URI.
     *
     * @property redirectUri Complete redirect URI with response parameters
     */
    @Serializable
    data class Redirect(
        val redirectUri: String,
    ) : SubmissionResult
}

/**
 * Exception thrown by Holder operations.
 *
 * @property message Error message
 * @property cause Optional underlying cause
 */
class Oid4vpHolderException(
    message: String,
    cause: Throwable? = null,
) : Exception(message, cause)
