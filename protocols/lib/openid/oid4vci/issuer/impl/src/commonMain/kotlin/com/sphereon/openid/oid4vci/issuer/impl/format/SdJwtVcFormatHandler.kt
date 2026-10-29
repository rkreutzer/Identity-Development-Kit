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

package com.sphereon.openid.oid4vci.issuer.impl.format

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.error.IdkError
import com.sphereon.crypto.core.kms.KeyManagerService
import com.sphereon.crypto.jose.jws.command.CreateJwsOpts
import com.sphereon.crypto.resolution.managed.ManagedOptsAlias
import com.sphereon.di.session.SessionScope
import com.sphereon.did.manager.DidCreateOptions
import com.sphereon.did.manager.DidProviderRegistry
import com.sphereon.did.models.VerificationPurpose
import com.sphereon.openid.oid4vc.common.CredentialFormat
import com.sphereon.openid.oid4vci.common.model.CredentialConfigurationSupported
import com.sphereon.openid.oid4vci.common.model.CredentialRequest
import com.sphereon.openid.oid4vci.issuer.format.CredentialEnvelope
import com.sphereon.openid.oid4vci.issuer.format.CredentialFormatHandler
import com.sphereon.openid.oid4vci.issuer.format.IssuanceContext
import com.sphereon.openid.oid4vci.issuer.format.SdPolicy
import com.sphereon.openid.oid4vci.issuer.format.SigningKeyMode
import com.sphereon.sdjwt.IssueSdJwtArgs
import com.sphereon.sdjwt.SdJwtService
import com.sphereon.sdjwt.dsl.sdJwtPayload
import com.sphereon.statuslist.spi.CredentialStatusEnricher
import dev.zacsweers.metro.ContributesIntoSet
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.Provider
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlin.time.Clock
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/**
 * IETF SD-JWT VC format handler (`dc+sd-jwt`).
 *
 * `vc+sd-jwt` is the distinct W3C VCDM 2.0 representation defined by VC JOSE/COSE
 * and must not be routed through this `vct`-based handler.
 */
@Inject
@SingleIn(SessionScope::class)
@ContributesIntoSet(SessionScope::class, binding = binding<CredentialFormatHandler>())
@OptIn(ExperimentalUuidApi::class)
class SdJwtVcFormatHandler(
    private val sdJwtService: SdJwtService,
    private val kms: KeyManagerService,
    private val didProviderRegistry: DidProviderRegistry,
    private val issuerKeyIdResolver: com.sphereon.openid.oid4vci.issuer.impl.signing.IssuerKeyIdResolver,
    private val statusEnricherProvider: Provider<CredentialStatusEnricher>? = null,
) : CredentialFormatHandler {
    override val supportedFormat: String = CredentialFormat.SD_JWT_VC.value

    override suspend fun canHandle(
        request: CredentialRequest,
        configuration: CredentialConfigurationSupported,
    ): Boolean = configuration.format == CredentialFormat.SD_JWT_VC.value

    override suspend fun issueCredential(
        request: CredentialRequest,
        context: IssuanceContext,
    ): IdkResult<CredentialEnvelope, IdkError> {
        val vct =
            context.credentialConfiguration.vct
                ?: return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "vct is required for the IETF SD-JWT VC format"))

        // DIIP v5 Appendix B: a federation-entity issuer owns the `fed` claim. An attribute of the
        // same name would either be emitted as a disclosure or collide with the issuer's own value.
        val federationEntityIdentifier = context.federationEntityIdentifier
        if (federationEntityIdentifier != null && context.attributes.containsKey(FED_CLAIM)) {
            return Err(
                IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message = "the $FED_CLAIM claim is set by a federation-entity issuer and cannot be supplied as an attribute",
                ),
            )
        }

        // Server-resolved signing key. The same name backs the `iss` DID and the JWT header, so a
        // credential can never be signed under one identity and advertised under another.
        val keyAlias = context.requireSigningKeyName().getOrElse { return Err(it) }

        // Apply clock-skew tolerance and round to an hour boundary per RFC 9901 §10.1 so
        // credentials issued together do not expose a precise shared issuance instant.
        // Whole-day validity periods keep `exp` on the same coarse boundary.
        val iat =
            roundedCredentialIssuanceEpochSeconds(
                nowEpochSeconds = Clock.System.now().epochSeconds,
                issuanceClockSkewInSeconds = context.issuanceClockSkewInSeconds,
            )

        // The SD-JWT `iss` claim: per SD-JWT VC §3.5 it MUST be resolvable to the signing
        // key. It MAY be an HTTPS URL (resolved via /.well-known/jwt-vc-issuer) OR a DID
        // URL (resolved via the DID method). When the issuer is configured to sign with a
        // DID-based key mode (`did:jwk`, `did:key`, etc.), we emit the DID URL as `iss` so
        // `iss` and the header `kid` are consistently rooted in the same DID. Wallets
        // like credo-ts that only support did-based issuer resolution require this. The
        // OID4VCI Credential Issuer Identifier (used in `credential_issuer`, offers, and
        // metadata discovery) remains the HTTPS URL and is unaffected.
        val signingMode = context.signingKeyMode
        val signingVerificationMethodId =
            if (signingMode is SigningKeyMode.Did) {
                val selected =
                    context.signingVerificationMethodId
                        ?: return Err(
                            IdkError.fromString(
                                code = "invalid_signing_verification_method",
                                message = "DID signing requires an exact assertionMethod verification method",
                            ),
                        )
                issuerKeyIdResolver.validateDidVerificationMethodId(keyAlias, selected).getOrElse { return Err(it) }
            } else {
                null
            }
        val issClaim: String =
            if (signingMode is SigningKeyMode.Did) {
                signingVerificationMethodId!!.substringBefore('#')
            } else {
                context.issuerIdentifier
            }
        // exp is only emitted when the credential configuration specifies a validity window.
        // Per SD-JWT VC §3.2.2 / RFC 7519 §4.1.4 `exp` is OPTIONAL — absence means no
        // expiration check applies.
        val exp: Long? = context.expirationInDays?.let { iat + it.toLong() * SECONDS_PER_DAY }

        // Pre-sign: reserve a Token Status List entry (if configured) so the `status.status_list`
        // reference is embedded into the signed SD-JWT.
        val statusEnricher = statusEnricherProvider?.invoke()
        val reservedStatus =
            reserveCredentialStatus(statusEnricher, context).getOrElse { return Err(it) }
        var statusBound = reservedStatus == null
        try {
        val credentialId = reservedStatus?.let { Uuid.random().toString() }

        // Build the SD-JWT payload using the DSL
        val payload =
            sdJwtPayload {
                // Standard JWT claims (never SD per RFC 9901 Section 9.7)
                iss(issClaim)
                claim("vct", vct)
                // OpenID Federation Entity Identifier (DIIP v5 Appendix B), always disclosed: a
                // verifier needs it to build the issuer's trust chain before it trusts any claim.
                // `iss` keeps naming the signing identity.
                federationEntityIdentifier?.let { claim(FED_CLAIM, it) }
                credentialId?.let { claim("jti", it) }
                iat(iat)
                if (exp != null) claim("exp", exp)
                // Status list reference — a standard, never-selectively-disclosed claim.
                reservedStatus?.let { claim("status", it.claim) }
                // Holder binding: cnf carries EXACTLY ONE of `kid` (DID VM URL) or `jwk`,
                // matching the method the wallet used in its proof. Wallet libraries such
                // as credo-ts pick the first branch they find — including both with `jwk`
                // first makes them treat the binding as `method: jwk` and then fail to
                // locate the wallet's internal key (the wallet keyed its key by the DID,
                // not by thumbprint).
                //
                //   - DID-bound proof (kid = did:...#vm)  → cnf = { kid: <did-url> }
                //                                           sub = <did without fragment>
                //   - jwk-bound proof                     → cnf = { jwk: <public jwk> }
                //                                           sub omitted (proof's `iss`
                //                                           is wallet client_id, not the
                //                                           credential subject)
                context.holderBindingKey?.let { key ->
                    val holderKid = context.holderKeyId
                    val isDid = holderKid != null && holderKid.startsWith("did:")
                    if (isDid) {
                        claim("sub", holderKid!!.substringBefore('#'))
                        claim(
                            "cnf",
                            buildJsonObject { put("kid", JsonPrimitive(holderKid)) },
                        )
                    } else {
                        claim(
                            "cnf",
                            buildJsonObject { put("jwk", key) },
                        )
                    }
                }

                // Add attributes, respecting SD policies
                for ((name, value) in context.attributes) {
                    val policy = context.sdPolicies[name] ?: SdPolicy.SELECTIVELY_DISCLOSABLE
                    when (policy) {
                        SdPolicy.ALWAYS_DISCLOSED -> {
                            claim(name, value)
                        }

                        SdPolicy.SELECTIVELY_DISCLOSABLE -> {
                            claimSd(name, value)
                        }

                        SdPolicy.NEVER_DISCLOSED -> { /* skip entirely */ }
                    }
                }
            }

        val issuerKey = ManagedOptsAlias(identifier = keyAlias)

        // Resolve signing key identifier for the JWT protected header, then merge in the
        // SD-JWT VC `typ` header. Per draft-ietf-oauth-sd-jwt-vc §3.1 the JWT MUST carry
        // `vc+sd-jwt` has distinct W3C VCDM payload semantics and is not an alias
        // accepted by this IETF SD-JWT VC handler.
        val keyIdentifierHeader =
            resolveIssuerSigningHeader(
                kms = kms,
                issuerKeyIdResolver = issuerKeyIdResolver,
                keyAlias = keyAlias,
                mode = context.signingKeyMode,
                signingVerificationMethodId = signingVerificationMethodId,
                configuredX5c = context.signingX5c,
            ).getOrElse { return Err(it) }
        val signingHeader: JsonObject =
            buildJsonObject {
                put("typ", JsonPrimitive(CredentialFormat.SD_JWT_VC.value))
                keyIdentifierHeader?.forEach { (k, v) -> put(k, v) }
            }

        val result =
            sdJwtService
                .issueSdJwt(
                    IssueSdJwtArgs(
                        payload = payload,
                        issuer = issuerKey,
                        opts =
                            CreateJwsOpts(
                                protectedHeader = signingHeader,
                                noIdentifierInHeader = keyIdentifierHeader != null,
                            ),
                    ),
                ).getOrElse { return Err(it) }

        reservedStatus?.let { reserved ->
            checkNotNull(statusEnricher)
                .bind(reserved.handle, credentialId = credentialId, credentialHash = null)
                .getOrElse { return Err(it) }
        }
        statusBound = true

        return Ok(
            CredentialEnvelope(
                credential = JsonPrimitive(result.sdJwt),
                format = context.credentialConfiguration.format,
            ),
        )
        } finally {
            if (!statusBound && reservedStatus != null) {
                try {
                    withContext(NonCancellable) { checkNotNull(statusEnricher).cancel(reservedStatus.handle) }
                } catch (_: Exception) {
                    // Cleanup must never replace the validation/signing/bind error that caused it.
                }
            }
        }
    }

    companion object {
        private const val SECONDS_PER_DAY: Long = 24L * 60L * 60L

        /** SD-JWT VC claim carrying the issuer's OpenID Federation Entity Identifier (DIIP v5 Appendix B). */
        const val FED_CLAIM: String = "fed"
    }
}
