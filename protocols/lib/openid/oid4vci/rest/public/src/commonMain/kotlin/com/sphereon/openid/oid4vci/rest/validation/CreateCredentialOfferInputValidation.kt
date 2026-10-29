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

package com.sphereon.openid.oid4vci.rest.validation

import com.sphereon.openid.oid4vci.issuer.config.requireCanonicalOid4vciIssuerInstanceId
import com.sphereon.openid.oid4vci.rest.CreateCredentialOfferInput
import io.konform.validation.Validation
import io.konform.validation.constraints.maximum
import io.konform.validation.constraints.minimum
import io.konform.validation.ifPresent

/** The bounds the create credential offer input keeps, which the OpenAPI schema repeats. */
object CreateCredentialOfferLimits {
    /** The longest offer lifetime in seconds, 365 days. Anything longer is a mistake, and the expiry arithmetic must not overflow. */
    const val TTL_SECONDS_MAX: Long = 31_536_000
}

/**
 * The rules of [CreateCredentialOfferInput] that need nothing but the input. Rules that compare the input with the
 * issuer instance the request is bound to stay with the command, because they need that state.
 */
val validateCreateCredentialOfferInput: Validation<CreateCredentialOfferInput> =
    Validation {
        CreateCredentialOfferInput::ttlSeconds ifPresent {
            minimum(1L) hint "ttl_seconds must be at least 1"
            maximum(CreateCredentialOfferLimits.TTL_SECONDS_MAX) hint
                "ttl_seconds must not exceed ${CreateCredentialOfferLimits.TTL_SECONDS_MAX}"
        }
        CreateCredentialOfferInput::issuerInstanceId ifPresent {
            constrain("issuer_instance_id must be a canonical UUID") {
                runCatching { requireCanonicalOid4vciIssuerInstanceId(it) }.isSuccess
            }
        }
    }
