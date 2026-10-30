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

package com.sphereon.openid.oid4vci.issuer.impl.command

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.error.IdkError
import com.sphereon.openid.oid4vci.issuer.spi.IssuerFederationEntityResolver
import kotlin.coroutines.cancellation.CancellationException

/**
 * The Entity Identifier the issuance names in its credentials, or null when the issuer is not an
 * OpenID Federation entity or no resolver is bound.
 *
 * DIIP v5 Appendix B fixes the Entity Identifier to the `credential_issuer` value, so an answer
 * naming anything else is refused instead of being placed in a signed credential. A resolver that
 * throws is treated like one that reports a failure: the request fails rather than silently issuing
 * a credential without the federation content the profile requires.
 */
internal suspend fun resolveIssuerFederationEntityIdentifier(
    resolver: IssuerFederationEntityResolver?,
    credentialIssuer: String,
): IdkResult<String?, IdkError> {
    if (resolver == null) return Ok(null)
    val resolved =
        try {
            resolver.resolveFederationEntityIdentifier(credentialIssuer)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return Err(federationEntityUnresolved(e))
        }
    if (resolved.isErr) return Err(resolved.error)
    val identifier = resolved.value ?: return Ok(null)
    if (identifier != credentialIssuer) {
        return Err(
            IdkError.fromString(
                code = "issuer_federation_entity_mismatch",
                message = "the federation Entity Identifier of a Credential Issuer must be its credential_issuer value",
            ),
        )
    }
    return Ok(identifier)
}

private fun federationEntityUnresolved(cause: Exception): IdkError =
    IdkError.SERVICE_UNAVAILABLE_ERROR(
        message = "the OpenID Federation entity status of the credential issuer could not be determined",
        throwable = cause,
    )
