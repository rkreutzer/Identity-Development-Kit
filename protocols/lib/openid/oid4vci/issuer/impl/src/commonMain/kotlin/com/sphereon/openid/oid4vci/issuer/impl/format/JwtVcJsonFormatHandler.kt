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
import com.sphereon.crypto.core.KeyInfo
import com.sphereon.crypto.core.sign.SignatureService
import com.sphereon.crypto.core.sign.model.SignInput
import com.sphereon.crypto.core.sign.model.JwsSignatureParameters
import com.sphereon.crypto.jose.jws.command.CreateJwsOpts
import com.sphereon.crypto.resolution.managed.ManagedOptsAlias
import com.sphereon.di.session.SessionScope
import com.sphereon.openid.oid4vc.common.CredentialFormat
import com.sphereon.openid.oid4vc.common.vcdm.VcdmProfiles
import com.sphereon.openid.oid4vc.common.vcdm.VcdmUris
import com.sphereon.openid.oid4vc.common.vcdm.VcdmVersion
import com.sphereon.openid.oid4vci.common.model.CredentialConfigurationSupported
import com.sphereon.openid.oid4vci.common.model.CredentialRequest
import com.sphereon.openid.oid4vci.issuer.format.CredentialEnvelope
import com.sphereon.openid.oid4vci.issuer.format.CredentialFormatHandler
import com.sphereon.openid.oid4vci.issuer.format.IssuanceContext
import com.sphereon.openid.oid4vci.issuer.format.SigningKeyMode
import com.sphereon.openid.oid4vci.issuer.impl.signing.IssuerKeyIdResolver
import com.sphereon.statuslist.spi.CredentialStatusEnricher
import dev.zacsweers.metro.ContributesIntoSet
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.Provider
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlin.time.Clock
import kotlin.time.Instant
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/**
 * JWT VC JSON format handler (jwt_vc_json).
 *
 * Issues W3C Verifiable Credentials as JWTs using [SignatureService].
 */
@Inject
@SingleIn(SessionScope::class)
@ContributesIntoSet(SessionScope::class, binding = binding<CredentialFormatHandler>())
@OptIn(ExperimentalUuidApi::class)
class JwtVcJsonFormatHandler(
    private val signatureService: SignatureService,
    private val kms: KeyManagerService,
    private val issuerKeyIdResolver: IssuerKeyIdResolver,
    private val statusEnricherProvider: Provider<CredentialStatusEnricher>? = null,
) : CredentialFormatHandler {
    override val supportedFormat: String = CredentialFormat.JWT_VC_JSON.value

    override suspend fun canHandle(
        request: CredentialRequest,
        configuration: CredentialConfigurationSupported,
    ): Boolean = configuration.format == CredentialFormat.JWT_VC_JSON.value

    override suspend fun issueCredential(
        request: CredentialRequest,
        context: IssuanceContext,
    ): IdkResult<CredentialEnvelope, IdkError> {
        val credentialTypes =
            vcdmCredentialTypes(context.credentialConfiguration.credentialDefinition?.type)
                .getOrElse { return Err(it) }
        val suppliedProperties =
            mergeVcdmIssuanceProperties(context, VcdmVersion.V1_1)
                .getOrElse { return Err(it) }
        if (context.credentialSubjects.isNotEmpty() && context.attributes.isNotEmpty()) {
            return Err(
                IdkError.fromString(
                    code = "invalid_vcdm_credential",
                    message = "credentialSubjects and attributes cannot both be supplied",
                ),
            )
        }
        context.credentialId?.let {
            if (!VcdmUris.isValid(it)) {
                return Err(IdkError.fromString(code = "invalid_vcdm_identifier", message = "credentialId must be a URI"))
            }
        }
        val credentialSubjects = context.credentialSubjects.ifEmpty { listOf(JsonObject(context.attributes)) }
        if (credentialSubjects.size != 1) {
            return Err(
                IdkError.fromString(
                    code = "invalid_vcdm_credential",
                    message = "VCDM 1.1 jwt_vc_json requires exactly one credentialSubject object",
                ),
            )
        }
        // Cryptographic Holder Binding (OID4VCI 1.0 section 8.1, OID4VP 1.0): VCDM 1.1 JWTs define no
        // `cnf`; the only binding is the subject identifier, `sub` = `credentialSubject.id`
        // (VCDM 1.1 section 6.3.1). The proof's key must therefore be a DID verification method
        // (OID4VCI Appendix A.1.1 binds jwt_vc_json to DIDs), and that DID becomes the subject.
        val credentialSubject = holderBoundCredentialSubject(credentialSubjects.single(), context).getOrElse { return Err(it) }

        val nowEpochSeconds = Clock.System.now().epochSeconds
        val validityStart = context.validFrom ?: Instant.fromEpochSeconds(nowEpochSeconds)
        val validityEnd = context.validUntil ?: context.expirationInDays?.let { days ->
            Instant.fromEpochSeconds(validityStart.epochSeconds + days.toLong() * 24L * 60L * 60L)
        }
        // NumericDate has second precision. Use that same instant for the semantic issuanceDate
        // so the mandatory VCDM 1.1 nbf mapping is exact rather than approximately equal.
        val issuanceInstant = Instant.fromEpochSeconds(validityStart.epochSeconds)

        // Pre-sign: reserve a status-list entry (if configured) so its `credentialStatus` reference
        // is embedded into the signed credential.
        val statusEnricher = statusEnricherProvider?.invoke()
        val reservedStatus =
            reserveCredentialStatus(statusEnricher, context).getOrElse { return Err(it) }
        var statusBound = reservedStatus == null
        try {
        // VCDM credential identifiers are URIs. Use the same URI for the semantic VC id, the JWT
        // jti mapping, and the status-store binding so all three identify the issued credential.
        val credentialId = context.credentialId ?: reservedStatus?.let { "urn:uuid:${Uuid.random()}" }

        // Server-resolved signing key; a credential is never signed under a name derived from a
        // caller-visible identifier. The signing-key identifier header (kid / x5c) is derived from
        // `signingKeyMode` so verifiers can discover the public key — mirrors SdJwtVcFormatHandler.
        val keyAlias = context.requireSigningKeyName().getOrElse { return Err(it) }
        val issuerKey = ManagedOptsAlias(identifier = keyAlias)
        val signingVerificationMethodId =
            if (context.signingKeyMode is SigningKeyMode.Did) {
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
        // OID4VCI 1.0 §14.4: the Credential Issuer Identifier is always the HTTPS URL, while the
        // issuer identifier in the credential follows the signing key. A DID-signed credential
        // names its DID as `issuer`/`iss`, rooted in the same DID as the header `kid`, so the key
        // resolves through the DID document. Other modes keep the HTTPS identifier (X.509 keys
        // travel in `x5c`; otherwise issuer metadata). Mirrors SdJwtVcFormatHandler.
        val credentialIssuer =
            signingVerificationMethodId?.let { didOfVerificationMethod(it).getOrElse { error -> return Err(error) } }
                ?: context.issuerIdentifier

        // Build the W3C VC payload
        val vcPayload =
            buildJsonObject {
                putJsonArray("@context") {
                    add(JsonPrimitive("https://www.w3.org/2018/credentials/v1"))
                    if (reservedStatus != null) add(JsonPrimitive("https://www.w3.org/ns/credentials/status/v1"))
                }
                putJsonArray("type") {
                    credentialTypes.forEach { add(JsonPrimitive(it)) }
                }
                put("issuer", credentialIssuer)
                put("issuanceDate", issuanceInstant.toString())
                validityEnd?.let { put("expirationDate", it.toString()) }
                credentialId?.let { put("id", it) }
                suppliedProperties.forEach { (name, value) -> put(name, value) }
                reservedStatus?.let { put("credentialStatus", it.claim) }
                put("credentialSubject", credentialSubject)
            }

        val profileValidation = VcdmProfiles.v1_1.validateCredential(vcPayload)
        if (!profileValidation.valid) {
            val error = profileValidation.errors.firstOrNull()
            return Err(
                if (error != null) IdkError.fromDTO(error)
                else IdkError.fromString(
                    code = "invalid_vcdm_credential",
                    message = "VCDM 1.1 credential profile validation failed",
                ),
            )
        }

        // Build the full JWT payload with vc claim
        val jwtPayload =
            buildJsonObject {
                put("vc", vcPayload)
                put("iss", credentialIssuer)
                put("nbf", validityStart.epochSeconds)
                credentialId?.let { put("jti", it) }
                (credentialSubject["id"] as? JsonPrimitive)
                    ?.takeIf { it.isString }
                    ?.let { put("sub", it.content) }
                // Shift iat backward by the configured clock-skew so wallets with slightly-
                // ahead clocks still accept the credential on receipt.
                val iat = nowEpochSeconds - context.issuanceClockSkewInSeconds
                put("iat", iat)
                // Only emit `exp` when the configuration specifies a validity window.
                validityEnd?.let { put("exp", it.epochSeconds) }
            }

        val keyIdentifierHeader =
            resolveIssuerSigningHeader(
                kms = kms,
                issuerKeyIdResolver = issuerKeyIdResolver,
                keyAlias = keyAlias,
                mode = context.signingKeyMode,
                signingVerificationMethodId = signingVerificationMethodId,
                configuredX5c = context.signingX5c,
            ).getOrElse { return Err(it) }

        val protectedHeader =
            buildJsonObject {
                // VCDM 1.1 requires typ=JWT when typ is present. Emit it consistently so generic
                // JOSE processors do not confuse this legacy wrapper with VCDM 2.0 vc+jwt.
                put("typ", JsonPrimitive("JWT"))
                keyIdentifierHeader?.forEach { (name, value) -> put(name, value) }
            }

        val result =
            signatureService
                .sign(
                    signInput = SignInput(jwtPayload.toString().encodeToByteArray(), mimeType = "application/json"),
                    keyInfo = KeyInfo<Nothing>(alias = keyAlias),
                    parameters = JwsSignatureParameters(
                        issuer = issuerKey,
                        payload = jwtPayload,
                        opts =
                            CreateJwsOpts(
                                protectedHeader = protectedHeader,
                                noIdentifierInHeader = true,
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
                credential = JsonPrimitive(result.signedData.decodeToString()),
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

}

/**
 * The credential subject bound to the proof's holder DID, or the supplied subject when the request
 * carries no key proof. A bare JWK proof cannot be bound by a VCDM 1.1 JWT, and a supplied subject
 * id for someone other than the holder would leave the credential unbound; both are refused.
 */
private fun holderBoundCredentialSubject(subject: JsonObject, context: IssuanceContext): IdkResult<JsonObject, IdkError> {
    val holderKeyId = context.holderKeyId
    if (holderKeyId == null && context.holderBindingKey == null) return Ok(subject)
    if (holderKeyId == null || !holderKeyId.startsWith("did:")) {
        return Err(
            IdkError.fromString(
                code = "invalid_proof",
                message = "jwt_vc_json holder binding requires a key proof for a DID verification method",
            ),
        )
    }
    val holderDid = holderKeyId.substringBefore('#')
    val suppliedId = subject["id"]
    if (suppliedId != null && (suppliedId as? JsonPrimitive)?.takeIf { it.isString }?.content != holderDid) {
        return Err(
            IdkError.fromString(
                code = "invalid_vcdm_credential",
                message = "VCDM 1.1 holder binding requires credentialSubject.id to be the holder DID",
            ),
        )
    }
    return Ok(JsonObject(subject + ("id" to JsonPrimitive(holderDid))))
}
