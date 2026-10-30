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

package com.sphereon.statuslist

import com.sphereon.core.compat.JsExportCompat
import kotlinx.datetime.Instant
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/** The two supported credential status-list specifications. */
@Serializable
@JsExportCompat
enum class StatusListSpec(
    val value: String,
) {
    /** IETF Token Status List (`draft-ietf-oauth-status-list`). */
    @SerialName("token_status_list")
    TOKEN_STATUS_LIST("token_status_list"),

    /** W3C Bitstring Status List v1.0. */
    @SerialName("bitstring_status_list")
    BITSTRING_STATUS_LIST("bitstring_status_list"),
    ;

    companion object {
        fun fromValue(value: String): StatusListSpec? =
            entries.firstOrNull { spec ->
                spec.value.equals(value, ignoreCase = true) || spec.name.equals(value, ignoreCase = true)
            }
    }
}

/** ISO/IEC 18013-5 second-edition status mechanism selected for a Token Status List. */
@Serializable
@JsExportCompat
enum class MdocStatusListProfile(
    val value: String,
) {
    /** One-bit status list indexed by the status reference in the MSO. */
    @SerialName("status_list")
    STATUS_LIST("status_list"),

    /** Revocation list containing the binary identifiers of revoked MSOs. */
    @SerialName("identifier_list")
    IDENTIFIER_LIST("identifier_list"),
    ;

    companion object {
        fun fromValue(value: String): MdocStatusListProfile? =
            entries.firstOrNull {
                it.value.equals(value, ignoreCase = true) || it.name.equals(value, ignoreCase = true)
            }
    }
}

/** Media types for the hosted, signed status-list token, keyed by proof envelope. */
object StatusListContentTypes {
    const val STATUSLIST_JWT = "application/statuslist+jwt"
    const val STATUSLIST_CWT = "application/statuslist+cwt"
    const val IDENTIFIERLIST_CWT = "application/identifierlist+cwt"

    /** W3C Bitstring Status List Credential enveloped as a VC-JWT. */
    const val VC_JWT = "application/vc+jwt"
}

/** Proof envelope used to secure a status-list token. */
@Serializable
@JsExportCompat
enum class StatusProofFormat(
    val value: String,
    val contentType: String,
) {
    @SerialName("jwt")
    JWT("jwt", StatusListContentTypes.STATUSLIST_JWT),

    @SerialName("cwt")
    CWT("cwt", StatusListContentTypes.STATUSLIST_CWT),

    @SerialName("vc+jwt")
    VC_JWT("vc+jwt", StatusListContentTypes.VC_JWT),
}

/** Status purpose. Custom string purposes are carried verbatim via [value]. */
@Serializable
@JsExportCompat
enum class StatusPurpose(
    val value: String,
) {
    @SerialName("revocation")
    REVOCATION("revocation"),

    @SerialName("suspension")
    SUSPENSION("suspension"),

    @SerialName("message")
    MESSAGE("message"),

    @SerialName("refresh")
    REFRESH("refresh"),
    ;

    companion object {
        fun fromValue(value: String): StatusPurpose? = entries.firstOrNull { it.value == value }
    }
}

/** Where the signed status-list token is expected to be served. */
@Serializable
@JsExportCompat
enum class StatusListHostingMode(
    val value: String,
) {
    /** The platform public hosting endpoint serves the token at [CreateStatusListArgs.statusListUri]. */
    @SerialName("hosted")
    HOSTED("hosted"),

    /** The token is exported from management and hosted outside the platform. */
    @SerialName("export")
    EXPORT("export"),
    ;

    companion object {
        fun fromValue(value: String): StatusListHostingMode? =
            entries.firstOrNull { mode ->
                mode.value.equals(value, ignoreCase = true) || mode.name.equals(value, ignoreCase = true)
            }
    }
}

/** Canonical Token Status List status values (also the W3C revocation/suspension 0/1 convention). */
object StatusValues {
    const val VALID: Int = 0x00
    const val INVALID: Int = 0x01
    const val SUSPENDED: Int = 0x02
}

/** Default bit length of a new status list (W3C minimum; ample for Token Status List). */
const val DEFAULT_STATUS_LIST_LENGTH: Int = 131_072

/**
 * W3C Bitstring Status List minimum number of entries (bitstring length divided by `statusSize`), for
 * herd privacy. Not mandated by IETF Token Status List.
 */
const val MIN_BITSTRING_STATUS_LIST_ENTRIES: Int = 131_072

/**
 * Issuer configuration binding a credential type to a status list. When present on an issuance,
 * the OID4VCI format handler allocates an entry in [statusListCorrelationId] and embeds the
 * matching status claim into the credential before signing.
 */
@Serializable
@JsExportCompat
data class StatusListBinding(
    val statusListCorrelationId: String,
    val spec: StatusListSpec,
    val purposes: List<StatusPurpose> = listOf(StatusPurpose.REVOCATION),
    /** Optional ISO/IEC 18013-5 status mechanism carried by an mdoc MSO. */
    val mdocProfile: MdocStatusListProfile? = null,
    /** The proof envelope configured for the bound list; required for mso_mdoc bindings. */
    val proofFormat: StatusProofFormat? = null,
    /** Optional ISO aggregation endpoint carried in the MSO status reference. */
    val aggregationUri: String? = null,
)

// region status-claim models (embedded in issued credentials)

/** IETF Token Status List referenced-token claim: `status: { status_list: { idx, uri } }`. */
@Serializable
@JsExportCompat
data class TokenStatusListClaim(
    @SerialName("status_list")
    val statusList: TokenStatusListReference,
)

@Serializable
@JsExportCompat
data class TokenStatusListReference(
    @SerialName("idx")
    val idx: Int,
    @SerialName("uri")
    val uri: String,
)

/** W3C Bitstring Status List reference: a `credentialStatus` entry of type `BitstringStatusListEntry`. */
@Serializable
@JsExportCompat
data class BitstringStatusListEntry(
    @SerialName("id")
    val id: String? = null,
    @SerialName("type")
    val type: String = "BitstringStatusListEntry",
    @SerialName("statusPurpose")
    val statusPurpose: String,
    // W3C carries the index as a string.
    @SerialName("statusListIndex")
    val statusListIndex: String,
    @SerialName("statusListCredential")
    val statusListCredential: String,
)

// endregion

// region references

/**
 * Resolves a status list. Management operations resolve [id] or [correlationId] inside the current
 * tenant. The public token operation may additionally resolve a globally unique [statusListUri] by
 * its full hosting URL; that read-only path does not grant tenant-scoped management access.
 */
@Serializable
@JsExportCompat
data class StatusListRef(
    val id: String? = null,
    val correlationId: String? = null,
    val statusListUri: String? = null,
)

/**
 * Resolves a single entry. Provide [statusListId]/[correlationId] to pick the list, then one of
 * [statusListIndex], [entryCorrelationId], or [credentialId] to pick the entry within it.
 */
@Serializable
@JsExportCompat
data class EntryRef(
    val statusListId: String? = null,
    val correlationId: String? = null,
    val statusListIndex: Int? = null,
    val entryCorrelationId: String? = null,
    val credentialId: String? = null,
)

// endregion

// region results

/** Full result of creating or fetching a status list, including the signed, hostable token. */
@Serializable
@JsExportCompat
data class StatusListResult(
    val id: String,
    val correlationId: String,
    val spec: StatusListSpec,
    val purposes: List<StatusPurpose>,
    val proofFormat: StatusProofFormat,
    val hostingMode: StatusListHostingMode = StatusListHostingMode.HOSTED,
    val bitsPerStatus: Int,
    val length: Int,
    val issuer: String,
    val statusListUri: String,
    /** The signed status-list token (compact JWS / CWT / VC-JWT). */
    val signedToken: String,
    val contentType: String,
    val mdocProfile: MdocStatusListProfile? = null,
    val aggregationUri: String? = null,
    /** The persisted expiry used as the mdoc CWT `exp` claim, when configured. */
    val validUntil: Instant? = null,
)

/**
 * A hostable, signed status-list token plus the cache hint derived from its `ttl`/`exp`.
 *
 * [token] is the textual form (a compact JWS for JWT/VC-JWT; for a binary CWT it is the base64url of
 * the COSE_Sign1 bytes, for transport/debugging). [tokenBytes], when present, is the exact bytes to
 * serve on the wire — set for the binary CWT format. Use [rawBytes] to get the correct on-the-wire
 * bytes regardless of format.
 */
@Serializable
@JsExportCompat
data class StatusListToken(
    val token: String,
    val contentType: String,
    val ttlSeconds: Long? = null,
    val tokenBytes: ByteArray? = null,
    /** Publication mode of the same persisted list that supplied this token. */
    val hostingMode: StatusListHostingMode = StatusListHostingMode.HOSTED,
) {
    /** The exact bytes to serve: the binary [tokenBytes] when present (CWT), else the UTF-8 [token] (JWT/VC-JWT). */
    fun rawBytes(): ByteArray = tokenBytes ?: token.encodeToByteArray()
}

/** Lightweight projection for list endpoints (no embedded token). */
@Serializable
@JsExportCompat
data class StatusListSummary(
    val id: String,
    val correlationId: String,
    val spec: StatusListSpec,
    val purposes: List<StatusPurpose>,
    val proofFormat: StatusProofFormat,
    val hostingMode: StatusListHostingMode = StatusListHostingMode.HOSTED,
    val bitsPerStatus: Int,
    val length: Int,
    val issuedCount: Int,
    val remainingCapacity: Int,
    val createdAt: Instant,
    val updatedAt: Instant,
    val mdocProfile: MdocStatusListProfile? = null,
    val aggregationUri: String? = null,
)

/** A single allocated entry within a status list. */
@Serializable
@JsExportCompat
data class StatusListEntry(
    val statusListId: String,
    val statusListIndex: Int,
    val entryCorrelationId: String? = null,
    val credentialId: String? = null,
    val credentialHash: String? = null,
    val value: Int,
    val purpose: StatusPurpose,
    /** ISO mdoc identifier used by an Identifier List profile, when applicable. */
    val identifier: ByteArray? = null,
)

// endregion

// region filtering / paging

@Serializable
@JsExportCompat
data class StatusListFilter(
    val spec: StatusListSpec? = null,
    val purpose: StatusPurpose? = null,
    val correlationId: String? = null,
)

@Serializable
@JsExportCompat
enum class StatusListSortField {
    @SerialName("createdAt")
    CREATED_AT,

    @SerialName("updatedAt")
    UPDATED_AT,

    @SerialName("correlationId")
    CORRELATION_ID,
}

// endregion

// region command/SPI argument types

@Serializable
@JsExportCompat
data class CreateStatusListArgs(
    /** Required, unique business key for the whole list. */
    val correlationId: String,
    val spec: StatusListSpec,
    val purposes: List<StatusPurpose> = listOf(StatusPurpose.REVOCATION),
    val proofFormat: StatusProofFormat,
    val hostingMode: StatusListHostingMode = StatusListHostingMode.HOSTED,
    val issuer: String,
    /** Public URI this list is hosted at; embedded into the status claim of issued credentials. */
    val statusListUri: String,
    val length: Int = DEFAULT_STATUS_LIST_LENGTH,
    val bitsPerStatus: Int = 1,
    /**
     * KMS key alias for a deployment that manages its own signing keys. Ignored outright where a
     * [com.sphereon.statuslist.spi.StatusListSigningKeyNameResolver] is bound, since the server then
     * owns the key. Where none is bound it is required: a list with no key is refused rather than
     * signed under a name derived from [correlationId].
     */
    val signingKeyAlias: String? = null,
    /**
     * How the signing key is referenced in the token's JOSE header: `did:<method>` (emit the DID
     * verification-method id as `kid`), `x5c` (embed the certificate chain), `jwk-thumbprint`, or null
     * (let the KMS decide). This selects the verification material published for the status-list
     * token itself. It is
     * independent from the key and publication mode used to sign credentials that reference it.
     */
    val signingKeyMode: String? = null,
    /**
     * For DID signing modes, the verification-method URL used as the token's `kid`. Required to pin
     * the kid for did:web/did:webvh (not derivable from the key); a full DID URL is used verbatim, and
     * if omitted web/webvh default to `did:web:<host>#<resolved signing key name>`. did:jwk/did:key
     * derive it.
     */
    val signingVerificationMethodId: String? = null,
    /** Optional PEM cert-chain path for `x5c` mode when the KMS key carries no embedded chain. */
    val signingCertChainPath: String? = null,
    val ttlSeconds: Long? = null,
    val validFrom: Instant? = null,
    val validUntil: Instant? = null,
    /** Optional ISO/IEC 18013-5 profile; null retains the generic status-list behavior. */
    val mdocProfile: MdocStatusListProfile? = null,
    /** Optional ISO aggregation endpoint carried in the mdoc status-list payload. */
    val aggregationUri: String? = null,
)

/**
 * Reserve an entry in a list.
 *
 * [explicitIndex] `null` (the default) means **pick a random unused index** — sequential
 * allocation is intentionally not offered, since sequential status-list indices leak issuance
 * order/volume and enable cross-credential correlation of holders. A non-null [explicitIndex]
 * uses exactly that index and fails if it is out of range or already in use.
 */
@Serializable
@JsExportCompat
data class AllocateEntryArgs(
    val statusList: StatusListRef,
    val purpose: StatusPurpose = StatusPurpose.REVOCATION,
    val explicitIndex: Int? = null,
    val entryCorrelationId: String? = null,
    val credentialId: String? = null,
    val credentialHash: String? = null,
    val initialValue: Int = StatusValues.VALID,
    /** Binary MSO identifier required for an Identifier List profile. */
    val identifier: ByteArray? = null,
)

@Serializable
@JsExportCompat
data class UpdateEntryStatusArgs(
    val entry: EntryRef,
    /** New status value in `[0, 2^bitsPerStatus)`, e.g. [StatusValues.INVALID] to revoke. */
    val value: Int,
)

/** Semantic status change for the ergonomic revoke command (no raw status values). */
@Serializable
@JsExportCompat
enum class CredentialStatusAction(
    val value: Int,
) {
    /** Mark the credential revoked ([StatusValues.INVALID]). */
    REVOKE(StatusValues.INVALID),

    /** Temporarily suspend the credential ([StatusValues.SUSPENDED]). */
    SUSPEND(StatusValues.SUSPENDED),

    /** Clear revocation/suspension, returning to valid ([StatusValues.VALID]). */
    REACTIVATE(StatusValues.VALID),
}

/**
 * Ergonomic revoke/suspend/reactivate of a single credential's status, selecting the entry by
 * [EntryRef] (credentialId, entryCorrelationId, or index — plus the list). A semantic wrapper over
 * [UpdateEntryStatusArgs] so callers (e.g. an example issuer) need not know raw status values.
 */
@Serializable
@JsExportCompat
data class RevokeCredentialStatusArgs(
    val entry: EntryRef,
    val action: CredentialStatusAction = CredentialStatusAction.REVOKE,
)

@Serializable
@JsExportCompat
data class ListStatusListsArgs(
    val filter: StatusListFilter = StatusListFilter(),
    val limit: Int = 20,
    val offset: Int = 0,
    val sortField: StatusListSortField = StatusListSortField.CREATED_AT,
    val descending: Boolean = true,
)

/** Verifier-side: resolve the status value at [index] of the list hosted at [uri]. */
@Serializable
@JsExportCompat
data class ResolveStatusArgs(
    val uri: String,
    val index: Int = 0,
    val expectedPurpose: StatusPurpose? = null,
    /** W3C Bitstring `statusSize` declared by the credential's status entry; it takes precedence over the list's own value. */
    val expectedStatusSize: Int? = null,
    /** When null, the spec/format is inferred from the fetched token's media type / envelope. */
    val expectedSpec: StatusListSpec? = null,
    val expectedFormat: StatusProofFormat? = null,
    /** Optional ISO mdoc Identifier List key. When supplied, the identifier list is resolved by presence. */
    val identifier: ByteArray? = null,
    /**
     * Explicit trust anchors for an ISO mdoc revocation CWT signer. They are deliberately not
     * inferred from the CWT's protected x5chain: that chain is evidence, not a new root of trust.
     * Generic JWT/CWT resolution does not use this field and keeps its existing behavior.
     */
    val trustedCerts: Array<String>? = null,
    /**
     * Optional certificate pin supplied by an authenticated mdoc MSO. This is evidence that the
     * protected CWT chain is the expected chain, not a trust anchor. The resolver must still
     * validate [trustedCerts] and must reject a chain that does not contain this certificate.
     */
    val expectedCertificate: ByteArray? = null,
)

/** Verifier-side resolved status. */
@Serializable
@JsExportCompat
data class ResolvedStatus(
    val value: Int,
    val purpose: StatusPurpose? = null,
    /** True iff [value] == [StatusValues.VALID]. */
    val valid: Boolean,
    val statusListUri: String,
)

// endregion
