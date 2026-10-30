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

package com.sphereon.openid.oid4vp.verifier.impl

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.error.IdkError
import com.sphereon.di.session.SessionScope
import com.sphereon.jsonld.loader.LinkedDataDocumentLoader
import com.sphereon.jsonld.processor.JsonLdTypeExpander
import com.sphereon.openid.oid4vc.common.CredentialFormat
import com.sphereon.openid.oid4vp.dcql.DcqlCredentialQuery
import com.sphereon.openid.oid4vp.dcql.anyAlternativeSatisfiedBy
import com.sphereon.openid.oid4vp.dcql.typeValueAlternatives
import com.sphereon.openid.oid4vp.dcql.vctValues
import com.sphereon.openid.oid4vp.verifier.CredentialTypeMatcher
import com.sphereon.sdjwt.vc.SdJwtVcClaims
import com.sphereon.sdjwt.vc.SdJwtVcTypeMatcher
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import kotlinx.serialization.json.JsonObject

/**
 * Matches SD-JWT VC types through [SdJwtVcTypeMatcher], and W3C credential types by expanding the types of the
 * credential root through the JSON-LD contexts [documentLoader] serves.
 */
@Inject
@SingleIn(SessionScope::class)
@ContributesBinding(SessionScope::class)
class CredentialTypeMatcherImpl(
    private val sdJwtVcTypeMatcher: SdJwtVcTypeMatcher,
    documentLoader: LinkedDataDocumentLoader,
) : CredentialTypeMatcher {
    private val typeExpander = JsonLdTypeExpander(documentLoader)

    override suspend fun matches(
        credential: JsonObject,
        query: DcqlCredentialQuery,
    ): IdkResult<Boolean, IdkError> =
        when (query.format) {
            CredentialFormat.SD_JWT_VC.value -> matchesSdJwtVc(credential, query)
            CredentialFormat.JWT_VC_JSON.value, CredentialFormat.LDP_VC.value -> matchesW3c(credential, query)
            else -> Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Credential type matching is not defined for format '${query.format}'"))
        }

    private suspend fun matchesSdJwtVc(
        credential: JsonObject,
        query: DcqlCredentialQuery,
    ): IdkResult<Boolean, IdkError> {
        val vct = SdJwtVcClaims.vct(credential) ?: return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "The SD-JWT VC carries no usable vct claim"))
        val integrity = SdJwtVcClaims.vctIntegrity(credential).getOrElse { return Err(it) }
        val accepted = query.vctValues() ?: return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Query '${query.id}' has no usable vct_values"))
        return sdJwtVcTypeMatcher.matches(vct, accepted, integrity)
    }

    private suspend fun matchesW3c(
        credential: JsonObject,
        query: DcqlCredentialQuery,
    ): IdkResult<Boolean, IdkError> {
        val alternatives = query.typeValueAlternatives() ?: return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Query '${query.id}' has malformed type_values"))
        val type = credential["type"] ?: return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "The credential has no type"))
        val actual = typeExpander.expandedRootTypes(credential["@context"], type).getOrElse { return Err(it) }
        return Ok(alternatives.anyAlternativeSatisfiedBy(actual))
    }
}
