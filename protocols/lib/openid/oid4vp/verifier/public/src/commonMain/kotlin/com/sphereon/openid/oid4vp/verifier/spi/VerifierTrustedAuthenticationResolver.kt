/*
 * Copyright 2026 Sphereon International B.V.
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

package com.sphereon.openid.oid4vp.verifier.spi

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.error.IdkError
import com.sphereon.oauth2.common.model.AuthorizationRequest
import com.sphereon.openid.oid4vp.dcql.DcqlQuery
import com.sphereon.openid.oid4vp.verifier.CredentialIssuerAuthenticationLookup
import com.sphereon.openid.oid4vp.verifier.TrustedAuthenticationResolution

/**
 * Authoritative server-side context for resolving the holder and credential-issuer
 * authentication sources admitted by a verifier session.
 *
 * None of these values is a key selector. Implementations use them to locate pinned verifier
 * configuration and return already-admitted public authentication material.
 */
data class VerifierTrustedAuthenticationRequest(
    val tenantId: String,
    val verifierInstanceId: String,
    val verifierId: String? = null,
    val dcqlQueryId: String? = null,
    val templateId: String? = null,
    val originalRequest: AuthorizationRequest,
    val dcqlQuery: DcqlQuery,
    /** Optional exact mdoc selection; absent for session-wide resolution of constrained material. */
    val documentType: String? = null,
    val certificateProfiles: Set<String> = emptySet(),
)

/**
 * Resolves verifier-admitted authentication sources for one persisted OID4VP session.
 *
 * Deployments may resolve DID, JWK/JWKS, X.509, or managed-key identifiers through their
 * canonical identifier-resolution graph. Implementations must never trust key material obtained
 * from the submitted VP merely because it appears in a JOSE header or VCDM document. Resolution
 * errors are returned explicitly so the direct-post endpoint can fail closed.
 */
interface VerifierTrustedAuthenticationResolver {
    suspend fun resolveTrustedAuthentications(
        request: VerifierTrustedAuthenticationRequest,
    ): IdkResult<List<TrustedAuthenticationResolution>, IdkError>

    /**
     * Credential-issuer signing sources are resolved under credential-issuer trust policy.
     * Older implementations safely provide none until they implement this distinct source.
     */
    suspend fun resolveTrustedCredentialIssuerAuthentications(
        request: VerifierTrustedAuthenticationRequest,
    ): IdkResult<List<TrustedAuthenticationResolution>, IdkError> = Ok(emptyList())

    /**
     * Issuer-specific credential-issuer authentication for issuers that the session's pinned policy
     * admits but cannot enumerate in advance. Null (the default) means only the pre-resolved
     * [resolveTrustedCredentialIssuerAuthentications] material applies.
     */
    suspend fun credentialIssuerAuthenticationLookup(
        request: VerifierTrustedAuthenticationRequest,
    ): CredentialIssuerAuthenticationLookup? = null
}
