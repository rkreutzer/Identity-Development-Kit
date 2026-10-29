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

package com.sphereon.identity.matching.protection

import com.sphereon.core.compat.JsExportCompat
import com.sphereon.data.store.party.model.IdentifierProtectionMode
import com.sphereon.data.store.party.model.IdentifierType

/**
 * Resolves the [IdentifierProtectionPolicy] that applies to a given identifier type within a
 * tenant. Implementations may consult tenant configuration; the default supplies sensible
 * built-in choices so callers always receive a usable policy.
 */
@JsExportCompat
interface IdentifierProtectionPolicyService {
    /** Returns the policy governing how identifiers of [type] are protected for [tenantId]. */
    suspend fun policyFor(
        tenantId: String,
        type: IdentifierType,
    ): IdentifierProtectionPolicy
}

/**
 * Built-in [IdentifierProtectionPolicyService] with safe defaults and no tenant overrides.
 *
 * Defaults:
 * - PII, natural-person official identifiers, x509, and unknown identifiers are searchable
 *   encrypted values.
 * - Public protocol, business, and endpoint identifiers stay plaintext unless tenant policy
 *   overrides them. A DID is intentionally public protocol material: encrypting it makes
 *   management and trust-anchor responses expose only a blind index instead of the DID.
 */
class DefaultIdentifierProtectionPolicyService : IdentifierProtectionPolicyService {
    override suspend fun policyFor(
        tenantId: String,
        type: IdentifierType,
    ): IdentifierProtectionPolicy =
        when (type.value.lowercase()) {
            "email" -> {
                IdentifierProtectionPolicy(
                    identifierType = type,
                    mode = IdentifierProtectionMode.SEARCHABLE_ENCRYPTED,
                    normalization = NormalizationProfile.EMAIL,
                )
            }

            "phone" -> {
                IdentifierProtectionPolicy(
                    identifierType = type,
                    mode = IdentifierProtectionMode.SEARCHABLE_ENCRYPTED,
                    normalization = NormalizationProfile.PHONE_E164,
                )
            }

            "did" -> {
                IdentifierProtectionPolicy(
                    identifierType = type,
                    mode = IdentifierProtectionMode.PLAINTEXT,
                    normalization = NormalizationProfile.DID,
                )
            }

            "passkey_credential_id" -> {
                IdentifierProtectionPolicy(
                    identifierType = type,
                    mode = IdentifierProtectionMode.SEARCHABLE_ENCRYPTED,
                    normalization = NormalizationProfile.NONE,
                )
            }

            "x509",
            "pas",
            "idc",
            "pno",
            "tin",
            "tax",
            "eid",
            "natural_local",
            "iban",
            "iin",
            "pan" -> {
                IdentifierProtectionPolicy(
                    identifierType = type,
                    mode = IdentifierProtectionMode.SEARCHABLE_ENCRYPTED,
                    normalization = NormalizationProfile.NONE,
                )
            }

            // OID4VCI issuer identity is case-sensitive and includes the complete path.
            "oid4vci_issuer" -> {
                IdentifierProtectionPolicy(
                    identifierType = type,
                    mode = IdentifierProtectionMode.PLAINTEXT,
                    normalization = NormalizationProfile.NONE,
                )
            }

            "domain",
            "url",
            "website",
            "issuer",
            "oidc_issuer",
            "oidc_federation_entity",
            "verifier",
            "jwks_url" -> {
                IdentifierProtectionPolicy(
                    identifierType = type,
                    mode = IdentifierProtectionMode.PLAINTEXT,
                    normalization = NormalizationProfile.URL_HOST,
                )
            }

            "vat",
            "ntr",
            "psd",
            "lei",
            "legal_local",
            "eori",
            "euid",
            "vatin",
            "legal_tin",
            "excise",
            "iso6523_org_id",
            "vlei",
            "bic",
            "isni",
            "isin",
            "mic",
            "uuid",
            "oid",
            "iso15459_id",
            "vin",
            "wmi",
            "container_id" -> {
                IdentifierProtectionPolicy(
                    identifierType = type,
                    mode = IdentifierProtectionMode.PLAINTEXT,
                    normalization = NormalizationProfile.NONE,
                )
            }

            else -> {
                IdentifierProtectionPolicy(
                    identifierType = type,
                    mode = IdentifierProtectionMode.SEARCHABLE_ENCRYPTED,
                    normalization = NormalizationProfile.NONE,
                )
            }
        }
}
