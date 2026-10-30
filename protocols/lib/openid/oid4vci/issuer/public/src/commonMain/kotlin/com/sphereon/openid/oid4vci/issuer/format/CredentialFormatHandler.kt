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

package com.sphereon.openid.oid4vci.issuer.format

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.compat.JsExportCompat
import com.sphereon.core.compat.JsExportIgnoreCompat
import com.sphereon.openid.oid4vci.common.model.CredentialConfigurationSupported
import com.sphereon.openid.oid4vci.common.model.CredentialRequest
import com.sphereon.openid.oid4vci.issuer.proof.VerifiedKeyAttestation
import com.sphereon.statuslist.StatusListBinding
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlin.time.Instant

/**
 * SPI for format-specific credential issuance.
 *
 * Implementations registered via `@ContributesIntoSet` for each supported format.
 */
@JsExportCompat
interface CredentialFormatHandler {
    val supportedFormat: String

    suspend fun canHandle(
        request: CredentialRequest,
        configuration: CredentialConfigurationSupported,
    ): Boolean

    suspend fun issueCredential(
        request: CredentialRequest,
        context: IssuanceContext,
    ): IdkResult<CredentialEnvelope, IdkError>
}

/**
 * Context passed to format handlers during credential issuance.
 */
@JsExportCompat
data class IssuanceContext(
    /**
     * Authenticated authorization/token subject and issuance-correlation identity. This is not
     * the issuer, holder, credential id, or semantic VCDM `credentialSubject.id`.
     */
    val subject: String,
    val clientId: String,
    val issuerIdentifier: String,
    val credentialConfigurationId: String,
    val credentialConfiguration: CredentialConfigurationSupported,
    val holderBindingKey: JsonElement?,
    val holderIdentifier: String? = null,
    val holderKeyId: String? = null,
    val keyAttestation: VerifiedKeyAttestation? = null,
    @JsExportIgnoreCompat
    val attributes: Map<String, JsonElement>,
    @JsExportIgnoreCompat
    val sdPolicies: Map<String, SdPolicy> = emptyMap(),
    @JsExportIgnoreCompat
    val mandatoryClaims: Set<String> = emptySet(),
    /**
     * KMS key name this credential signs under, resolved server side before the issuance reaches a
     * handler. A handler only consumes it and refuses when it is null; there is no credential
     * configuration id, vct, or doctype to fall back on. Process-internal: never place it on a DTO,
     * a REST response, or any serializable model.
     */
    val signingKeyAlias: String? = null,
    /** Key reference mode for the signing key identifier in the JWT protected header. */
    val signingKeyMode: SigningKeyMode = SigningKeyMode.None,
    /** Exact assertionMethod verification-method URI selected for the signing key. */
    val signingVerificationMethodId: String? = null,
    /** Explicit Data Integrity cryptosuite for `ldp_vc` issuance. */
    val dataIntegrityCryptosuite: String? = null,
    /**
     * Resolved X.509 certificate chain in canonical x5c encoding (standard-base64 DER strings).
     * KMS-provided x5c takes precedence over this configured material.
     */
    val signingX5c: Array<String>? = null,
    /**
     * Issuer-wide clock-skew tolerance, in seconds. `iat` on issued credentials is shifted
     * backward by this many seconds so wallets whose clocks are slightly ahead still accept
     * the credential as valid on receipt. Defaults to 60.
     * YAML: `sphereon.oid4vci.issuer.issuance-clock-skew-in-seconds`.
     */
    val issuanceClockSkewInSeconds: Long = 60L,
    /**
     * Per-credential validity window in days. When non-null, the handler emits an `exp` claim and
     * derives an absent `validUntil` from the data-validity start plus `days * 86400`.
     * VCDM 1.1 maps the resulting end to both `expirationDate` and NumericDate `exp`; VCDM 2.0
     * keeps `validUntil` as data validity while `exp` remains an independent signature-lifetime
     * policy (currently aligned to the same configured duration). When null, no `exp` is emitted.
     * YAML: `sphereon.oid4vci.issuer.credentials.[<id>].expiration-in-days`.
     */
    val expirationInDays: Int? = null,
    /**
     * Optional VCDM data-validity start. This is independent from the JOSE signing `iat`; when
     * absent, format handlers default it to their signing clock. VCDM 2.0 calls this `validFrom`,
     * while VCDM 1.1 exposes the same instant as `issuanceDate` (and its required `nbf` mapping).
     */
    val validFrom: Instant? = null,
    /**
     * Optional VCDM data-validity end. VCDM 1.1 maps it to `expirationDate` and `exp`; VCDM 2.0
     * keeps it distinct from the optional JOSE signature-lifetime `exp`.
     */
    val validUntil: Instant? = null,
    /**
     * Optional binding to a credential status list. When set, the format handler MUST allocate a
     * status entry (via the `CredentialStatusEnricher`) and embed the status claim into the
     * credential before signing — and MUST fail the issuance when it cannot (enricher missing,
     * reservation failure, or a format without status support): a credential issued without its
     * status claim can never be revoked. Null means no status list for this credential.
    */
    val statusListBinding: StatusListBinding? = null,
    /**
     * Optional top-level VCDM properties supplied by the issuance pipeline. The JSON object is
     * intentionally lossless so application-specific extension terms survive issuance. Format
     * handlers reject server-controlled keys rather than allowing this input to override issuer,
     * subject, dates, identifiers, status, proof, or JOSE material.
     */
    @JsExportIgnoreCompat
    val vcdmProperties: kotlinx.serialization.json.JsonObject = kotlinx.serialization.json.JsonObject(emptyMap()),
    /**
     * Optional normalized VCDM credential-subject objects. When empty, a JWT VCDM handler creates
     * one subject object from [attributes]. Subject identifiers are never inferred from the
     * issuance/proof subject, holder key, issuer, or DID.
     */
    @JsExportIgnoreCompat
    val credentialSubjects: List<JsonObject> = emptyList(),
    /** Optional semantic VCDM credential identifier, emitted as VC `id` and JWT `jti`. */
    val credentialId: String? = null,
    /**
     * OpenID Federation Entity Identifier of the issuer, resolved server side through
     * [com.sphereon.openid.oid4vci.issuer.spi.IssuerFederationEntityResolver]. When set it equals
     * [issuerIdentifier] (DIIP v5 Appendix B) and handlers name it in the credential as issuer-signed,
     * never selectively disclosable content: the SD-JWT VC `fed` claim, or a VCDM `termsOfUse`
     * entry of type `OpenIDFederation`. Null for an issuer that is not a federation entity.
     */
    val federationEntityIdentifier: String? = null,
)

/**
 * Selective disclosure policy for a claim.
 */
@JsExportCompat
enum class SdPolicy {
    ALWAYS_DISCLOSED,
    SELECTIVELY_DISCLOSABLE,
    NEVER_DISCLOSED,
}

/**
 * Wrapper for an issued credential.
 */
@JsExportCompat
data class CredentialEnvelope(
    val credential: JsonElement,
    val format: String,
    val notificationId: String? = null,
    val deferred: Boolean = false,
)
