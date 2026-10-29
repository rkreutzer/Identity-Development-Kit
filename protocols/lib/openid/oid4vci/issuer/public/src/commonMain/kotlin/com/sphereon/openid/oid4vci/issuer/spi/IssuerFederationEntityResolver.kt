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

package com.sphereon.openid.oid4vci.issuer.spi

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.error.IdkError
import com.sphereon.di.session.SessionScope
import dev.zacsweers.metro.ContributesTo
import dev.zacsweers.metro.OptionalBinding

/**
 * Server-owned answer to whether a Credential Issuer is an OpenID Federation entity, and if so
 * under which Entity Identifier it issues.
 *
 * The OpenID Federation Digital Credentials Profile (DIIP v5, Appendix B) makes the Credential
 * Issuer's `credential_issuer` value its Entity Identifier, and requires an issuer that is a
 * federation entity to name that identifier in every credential: the `fed` claim of an SD-JWT VC
 * and a `termsOfUse` entry of type `OpenIDFederation` in a W3C VCDM credential. A wallet or
 * verifier uses it to find the issuer's trust chain; it does not change `iss` or the VCDM
 * `issuer`, which keep following the signing key.
 *
 * No implementation is bound by default, and an unbound resolver means "not a federation entity":
 * a standalone issuer issues exactly as it would without this seam. A deployment that publishes
 * Entity Configurations for its issuers binds one.
 *
 * Results:
 * - `Ok(identifier)`: the issuer is a federation entity. The identifier must equal
 *   [credentialIssuer]; the issuance pipeline refuses any other value rather than name an entity
 *   the issuer is not.
 * - `Ok(null)`: the issuer is not a federation entity, or the deployment cannot host federation
 *   entities at all. Credentials are issued without federation content.
 * - `Err`: membership could not be determined. Issuance is refused, because issuing would either
 *   omit content the profile requires or name an entity that may not exist.
 *
 * Implementations resolve against the tenant of the current session and never against a value a
 * credential request supplied.
 */
interface IssuerFederationEntityResolver {
    suspend fun resolveFederationEntityIdentifier(credentialIssuer: String): IdkResult<String?, IdkError>
}

/**
 * Exposes [IssuerFederationEntityResolver] as an optional graph accessor so the credential request
 * command's `IssuerFederationEntityResolver? = null` parameter resolves under the Metro nullable type
 * key. An implementation adds a second `binding<IssuerFederationEntityResolver?>()` contribution,
 * which overrides this default `null` whenever it is on the classpath.
 */
@ContributesTo(SessionScope::class)
interface IssuerFederationEntityResolverOptionalProvider {
    @OptionalBinding
    val optionalIssuerFederationEntityResolver: IssuerFederationEntityResolver? get() = null
}
