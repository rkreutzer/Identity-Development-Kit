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
import com.sphereon.openid.oid4vci.issuer.format.SigningKeyMode
import com.sphereon.core.api.error.IdkError
import com.sphereon.crypto.core.KeyInfo
import com.sphereon.crypto.core.sign.SignatureService
import com.sphereon.crypto.core.sign.model.SignInput
import com.sphereon.crypto.core.sign.model.JwsSignatureParameters
import com.sphereon.crypto.jose.jws.command.CreateJwsOpts
import com.sphereon.crypto.core.kms.KeyManagerService
import com.sphereon.crypto.resolution.managed.ManagedOptsAlias
import com.sphereon.di.session.SessionScope
import com.sphereon.jsonld.JsonLdError
import com.sphereon.jsonld.WellKnownContexts
import com.sphereon.jsonld.WellKnownCredentialTypes
import com.sphereon.jsonld.command.JsonLdContextValidator
import com.sphereon.jsonld.command.JsonLdSchemaValidator
import com.sphereon.jsonld.command.ValidateJsonLdContextInput
import com.sphereon.jsonld.command.ValidateJsonLdSchemaInput
import com.sphereon.openid.oid4vc.common.CredentialFormat
import com.sphereon.openid.oid4vc.common.vcdm.VcdmUris
import com.sphereon.openid.oid4vc.common.vcdm.VcdmProfiles
import com.sphereon.openid.oid4vc.common.vcdm.VcdmVersion
import com.sphereon.openid.oid4vc.common.vcdm.validateVcdm20JwtTemporalClaims
import com.sphereon.openid.oid4vci.common.model.CredentialConfigurationSupported
import com.sphereon.openid.oid4vci.common.model.CredentialRequest
import com.sphereon.openid.oid4vci.issuer.format.CredentialEnvelope
import com.sphereon.openid.oid4vci.issuer.format.CredentialFormatHandler
import com.sphereon.openid.oid4vci.issuer.format.IssuanceContext
import com.sphereon.openid.oid4vci.issuer.impl.signing.IssuerKeyIdResolver
import com.sphereon.statuslist.StatusListSpec
import com.sphereon.statuslist.spi.CredentialStatusEnricher
import com.sphereon.statuslist.spi.StatusClaimMergeTarget
import dev.zacsweers.metro.ContributesIntoSet
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.Provider
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import kotlin.time.Clock
import kotlin.time.Instant
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/**
 * `jwt_vc_json-ld` format handler — VCDM 2.0 + JSON-LD body enveloped via
 * JOSE per W3C VC JOSE/COSE Section 3.1.1.
 *
 * Pipeline on issuance:
 *
 * 1. Build the VCDM 2.0 credential body (JSON-LD with VCDM 2.0 vocabulary —
 *    `validFrom`/`validUntil`, no `iat`/`exp` shadow inside the VC).
 * 2. Validate the credential's `@context` chain against UNTP 0.7.0
 *    `@vocab` MUST-NOT, resolving remote references through the IDK
 *    `LinkedDataDocumentLoader` chain (built-in → cache → integrity-pin
 *    → HTTP). Failure aborts issuance.
 * 3. Validate the credential body against the JSON Schema registered for its
 *    `type` (when one is bundled). Failure aborts issuance with
 *    structured per-pointer violations.
 * 4. Merge JWT registered claims (`iss`/`iat`/`exp`/`cnf`) at the root of
 *    the JOSE payload, alongside the VC body fields. VC-JOSE-COSE §3.1.1
 *    treats the entire VC document as the JWT payload — there is no `vc`
 *    wrapper claim, unlike the VC 1.1 `jwt_vc_json` shape.
 * 5. Sign with JWS; emit the compact serialization.
 *
 * UNTP 0.7.0 mandates this format for issued credentials.
 */
@Inject
@SingleIn(SessionScope::class)
@ContributesIntoSet(SessionScope::class, binding = binding<CredentialFormatHandler>())
@OptIn(ExperimentalUuidApi::class)
class VcLdJsonJwtFormatHandler(
    private val signatureService: SignatureService,
    private val kms: KeyManagerService,
    private val issuerKeyIdResolver: IssuerKeyIdResolver,
    private val contextValidator: JsonLdContextValidator,
    private val schemaValidator: JsonLdSchemaValidator,
    private val statusEnricherProvider: Provider<CredentialStatusEnricher>? = null,
) : CredentialFormatHandler {
    override val supportedFormat: String = CredentialFormat.JWT_VC_JSON_LD.value

    override suspend fun canHandle(
        request: CredentialRequest,
        configuration: CredentialConfigurationSupported,
    ): Boolean = configuration.format == CredentialFormat.JWT_VC_JSON_LD.value

    override suspend fun issueCredential(
        request: CredentialRequest,
        context: IssuanceContext,
    ): IdkResult<CredentialEnvelope, IdkError> =
        issueCredentialAt(
            now = Clock.System.now(),
            request = request,
            context = context,
        )

    /** Internal deterministic seam used by conformance tests to exercise future validity periods. */
    internal suspend fun issueCredentialAt(
        now: Instant,
        request: CredentialRequest,
        context: IssuanceContext,
    ): IdkResult<CredentialEnvelope, IdkError> {
        val suppliedProperties =
            mergeVcdmIssuanceProperties(context, VcdmVersion.V2_0)
                .getOrElse { return Err(it) }
        if (context.statusListBinding?.spec == StatusListSpec.TOKEN_STATUS_LIST) {
            return Err(invalidVcdm("VCDM 2.0 JWT credentials require a Bitstring Status List credentialStatus"))
        }
        val credentialTypes =
            vcdmCredentialTypes(context.credentialConfiguration.credentialDefinition?.type)
                .getOrElse { return Err(it) }
        val primaryType = pickPrimaryType(credentialTypes)
        val nowEpochSeconds = now.epochSeconds
        val validFrom = context.validFrom ?: now
        val validUntil = context.validUntil ?: context.expirationInDays?.let { days ->
            Instant.fromEpochSeconds(validFrom.epochSeconds + days.toLong() * SECONDS_PER_DAY)
        }
        if (context.credentialSubjects.isNotEmpty() && context.attributes.isNotEmpty()) {
            return Err(invalidVcdm("credentialSubjects and attributes cannot both be supplied"))
        }
        context.credentialId?.let {
            if (!VcdmUris.isValid(it)) {
                return Err(invalidVcdmIdentifier("credentialId must be a URI"))
            }
        }
        val credentialSubjects = context.credentialSubjects.ifEmpty { listOf(JsonObject(context.attributes)) }
        // OID4VCI 1.0 §14.4: the Credential Issuer Identifier is always the HTTPS URL, while the
        // issuer identifier in the credential follows the signing key. A DID-signed credential
        // names its DID as `issuer`/`iss`, rooted in the same DID as the header `kid`; other modes
        // keep the HTTPS identifier. Mirrors SdJwtVcFormatHandler.
        val credentialIssuer = credentialIssuerIdentifier(context).getOrElse { return Err(it) }

        // Validate all caller-controlled properties before reserving a status entry. A failed
        // context/schema request must not consume an allocation that can never be bound.
        val unsignedVcBody =
            buildVcBody(
                BuildVcBodyInputs(
                    credentialTypes = credentialTypes,
                    issuer = credentialIssuer,
                    credentialSubjects = credentialSubjects,
                    attributes = context.attributes,
                    validFrom = validFrom,
                    validUntil = validUntil,
                    extraContexts = additionalContextsFor(context),
                    properties = suppliedProperties,
                ),
            )

        validateContextChain(unsignedVcBody).getOrElse { return Err(it) }
        validateAgainstSchema(unsignedVcBody, primaryType).getOrElse { return Err(it) }

        val statusEnricher = statusEnricherProvider?.invoke()
        val reservedStatus = reserveCredentialStatus(statusEnricher, context).getOrElse { return Err(it) }
        var statusBound = reservedStatus == null
        try {
        if (reservedStatus?.mergeTarget != null && reservedStatus.mergeTarget != StatusClaimMergeTarget.VC_CREDENTIAL_STATUS) {
            return Err(invalidVcdm("VCDM 2.0 JWT credentials require a credentialStatus-compatible status list"))
        }
        // VCDM credential identifiers are URIs. Use the same URI for the semantic VC id, the JWT
        // jti mapping, and the status-store binding so all three identify the issued credential.
        val credentialId = context.credentialId ?: reservedStatus?.let { "urn:uuid:${Uuid.random()}" }
        val vcBody =
            if (credentialId != null || reservedStatus != null) {
                val statusProperties: Map<String, JsonElement> =
                    reservedStatus?.let { reserved ->
                        mapOf(
                            "credentialStatus" to reserved.claim,
                        )
                    } ?: emptyMap()
                JsonObject(
                    unsignedVcBody +
                        mapOf(
                            "id" to JsonPrimitive(checkNotNull(credentialId)),
                        ) + statusProperties,
                )
            } else {
                unsignedVcBody
            }
        // The configured schema may constrain optional identifier/status properties, so validate
        // again after those fragments have been merged and before constructing JWT claims.
        if (credentialId != null || reservedStatus != null) {
            validateAgainstSchema(vcBody, primaryType).getOrElse { return Err(it) }
        }

        val jwtPayload = buildJwtPayload(vcBody, context, credentialIssuer, nowEpochSeconds, credentialId)
        validateVcdm2JwtPayload(jwtPayload).getOrElse { return Err(it) }
        val envelope = signEnvelope(jwtPayload, context).getOrElse { return Err(it) }
        reservedStatus?.let { reserved ->
            checkNotNull(statusEnricher)
                .bind(reserved.handle, credentialId = credentialId, credentialHash = null)
                .getOrElse { return Err(it) }
        }
        statusBound = true
        return Ok(envelope)
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

    private fun pickPrimaryType(credentialTypes: List<String>): String =
        credentialTypes.firstOrNull { it != WellKnownCredentialTypes.VERIFIABLE_CREDENTIAL }
            ?: credentialTypes.first()

    /**
     * Validate @context chain (UNTP 0.7.0 @vocab MUST-NOT).
     */
    private suspend fun validateContextChain(vcBody: JsonObject): IdkResult<Unit, IdkError> {
        val verdict =
            contextValidator.validate(
                ValidateJsonLdContextInput(context = vcBody["@context"] ?: JsonArray(emptyList())),
            )
        if (verdict.isErr) {
            return Err(IdkError.fromDTO(verdict.error))
        }
        return Ok(Unit)
    }

    /**
     * Validate JSON Schema for the primary credential type. Unknown types (no schema in
     * the registry) are a soft pass: experimental or non-UNTP credentials issue without
     * schema enforcement. Schema mismatches and malformed schemas abort issuance.
     */
    private suspend fun validateAgainstSchema(
        vcBody: JsonObject,
        primaryType: String,
    ): IdkResult<Unit, IdkError> {
        val verdict =
            schemaValidator.validate(
                ValidateJsonLdSchemaInput(payload = vcBody, credentialType = primaryType),
            )
        return when {
            verdict.isOk -> Ok(Unit)
            verdict.error is JsonLdError.NoSchemaRegistered -> Ok(Unit)
            else -> Err(IdkError.fromDTO(verdict.error))
        }
    }

    /**
     * Build JWT payload: VC body fields at the root + JWT registered claims
     * (`iss`/`iat`/`exp`/`cnf`). VC-JOSE-COSE §3.1.1 treats the entire VC document
     * as the JWT payload — there is no `vc` wrapper claim.
     */
    private fun buildJwtPayload(
        vcBody: JsonObject,
        context: IssuanceContext,
        credentialIssuer: String,
        nowEpochSeconds: Long,
        credentialId: String?,
    ): JsonObject =
        buildJsonObject {
            // Spread VC body keys at the root.
            for ((k, v) in vcBody) put(k, v)

            put("iss", credentialIssuer)
            credentialId?.let { put("jti", it) }
            val didKid = context.holderKeyId?.takeIf { it.startsWith("did:") }
            // iat shifted backward by clock-skew tolerance.
            val iat = nowEpochSeconds - context.issuanceClockSkewInSeconds
            put("iat", iat)
            context.expirationInDays?.let { days ->
                // VC-JOSE-COSE defines exp as the signature expiration, independently of VCDM
                // validUntil. This issuer policy starts the configured duration at the data
                // validity start when one is supplied, so a future validity window cannot produce
                // a signature that expires before the credential becomes valid.
                val signatureStart = context.validFrom?.epochSeconds ?: nowEpochSeconds
                put("exp", signatureStart + days.toLong() * SECONDS_PER_DAY)
            }
            // Holder binding: cnf carries EITHER kid (DID VM URL) OR jwk,
            // never both — wallet libs (credo-ts and others) misbehave when
            // both are present.
            context.holderBindingKey?.let { key ->
                putJsonObject("cnf") {
                    if (didKid != null) {
                        put("kid", JsonPrimitive(didKid))
                    } else {
                        put("jwk", key)
                    }
                }
            }
        }

    private suspend fun credentialIssuerIdentifier(context: IssuanceContext): IdkResult<String, IdkError> {
        if (context.signingKeyMode !is SigningKeyMode.Did) return Ok(context.issuerIdentifier)
        val keyAlias = context.requireSigningKeyName().getOrElse { return Err(it) }
        val selected =
            context.signingVerificationMethodId
                ?: return Err(
                    IdkError.fromString(
                        code = "invalid_signing_verification_method",
                        message = "DID signing requires an exact assertionMethod verification method",
                    ),
                )
        val verificationMethodId = issuerKeyIdResolver.validateDidVerificationMethodId(keyAlias, selected).getOrElse { return Err(it) }
        return didOfVerificationMethod(verificationMethodId)
    }

    private suspend fun signEnvelope(
        jwtPayload: JsonObject,
        context: IssuanceContext,
    ): IdkResult<CredentialEnvelope, IdkError> {
        // Server-resolved signing key; the credential configuration id names a configuration, never
        // key material.
        val issuerKey = ManagedOptsAlias(identifier = context.requireSigningKeyName().getOrElse { return Err(it) })
        val keyIdentifierHeader =
            resolveIssuerSigningHeader(
                kms = kms,
                issuerKeyIdResolver = issuerKeyIdResolver,
                keyAlias = issuerKey.identifier,
                mode = context.signingKeyMode,
                signingVerificationMethodId = context.signingVerificationMethodId,
                configuredX5c = context.signingX5c,
            ).getOrElse { return Err(it) }
        val protectedHeader =
            buildJsonObject {
                put("typ", JsonPrimitive("vc+jwt"))
                put("cty", JsonPrimitive("vc"))
                keyIdentifierHeader?.forEach { (name, value) -> put(name, value) }
            }
        val signed =
            signatureService
                .sign(
                    signInput = SignInput(jwtPayload.toString().encodeToByteArray(), mimeType = "application/json"),
                    keyInfo = KeyInfo<Nothing>(alias = context.requireSigningKeyName().getOrElse { return Err(it) }),
                    parameters = JwsSignatureParameters(
                        issuer = issuerKey,
                        payload = jwtPayload,
                        opts = CreateJwsOpts(
                            protectedHeader = protectedHeader,
                            noIdentifierInHeader = keyIdentifierHeader != null,
                        ),
                    ),
                ).getOrElse { return Err(it) }
        return Ok(
            CredentialEnvelope(
                credential = JsonPrimitive(signed.signedData.decodeToString()),
                format = context.credentialConfiguration.format,
            ),
        )
    }

    /**
     * Grouped inputs for [buildVcBody] — avoids LongParameterList while keeping the
     * builder a pure function over its inputs. Internal-only, not serialized.
     */
    private data class BuildVcBodyInputs(
        val credentialTypes: List<String>,
        val issuer: String,
        val credentialSubjects: List<JsonObject>,
        val attributes: Map<String, kotlinx.serialization.json.JsonElement>,
        val validFrom: Instant,
        val validUntil: Instant?,
        val extraContexts: List<String>,
        val properties: JsonObject,
    )

    private fun buildVcBody(inputs: BuildVcBodyInputs): JsonObject =
        buildJsonObject {
            putJsonArray("@context") {
                // VCDM 2.0 base @context is mandatory and first.
                add(JsonPrimitive(WellKnownContexts.VCDM_2_0))
                for (ctx in inputs.extraContexts) {
                    if (ctx != WellKnownContexts.VCDM_2_0) {
                        add(JsonPrimitive(ctx))
                    }
                }
            }
            putJsonArray("type") {
                inputs.credentialTypes.forEach { add(JsonPrimitive(it)) }
            }
            put("issuer", inputs.issuer)
            put("validFrom", inputs.validFrom.toString())
            inputs.validUntil?.let { put("validUntil", it.toString()) }
            inputs.properties.forEach { (name, value) -> put(name, value) }
            val subjects = inputs.credentialSubjects.ifEmpty { listOf(JsonObject(inputs.attributes)) }
            put("credentialSubject", if (subjects.size == 1) subjects.single() else JsonArray(subjects))
        }

    /**
     * Pull additional `@context` IRIs from
     * `credentialConfiguration.credentialDefinition.@context`. The
     * configuration may declare extra contexts (e.g. UNTP DPP) that should
     * appear after the VCDM 2.0 base.
     */
    private fun additionalContextsFor(context: IssuanceContext): List<String> =
        context.credentialConfiguration.credentialDefinition
            ?.context
            ?.filter { it.isNotBlank() }
            ?: emptyList()

    private companion object {
        const val SECONDS_PER_DAY = 24L * 60L * 60L
    }
}

/**
 * Validate the complete VCDM 2.0 credential that is about to become the JWT payload.
 *
 * This deliberately runs after the VC body and JWT registered claims have been merged. The
 * profile catches VCDM shape/version errors, while this boundary catches the cross-envelope
 * consistency rules which cannot be expressed by the JSON-LD profile alone. Unknown extension
 * properties are intentionally not traversed or rewritten.
 */
internal fun validateVcdm2JwtPayload(payload: JsonObject): IdkResult<Unit, IdkError> {
    val profile = VcdmProfiles.v2_0.validateCredential(payload)
    if (!profile.valid) {
        val error = profile.errors.firstOrNull()
        return Err(
            if (error != null) IdkError.fromDTO(error)
            else invalidVcdm("VCDM 2.0 credential profile rejected the document"),
        )
    }

    validateVcdm20JwtTemporalClaims(payload).getOrElse { return Err(it) }
    val issuerElement = payload["issuer"] ?: return Err(invalidVcdm("issuer is required"))
    val issuerIdentifier = extractIssuerId(issuerElement)
    if (issuerIdentifier == null) {
        return Err(inconsistentJwtClaim("issuer must be a string or an object with a string id"))
    }
    if (!VcdmUris.isValid(issuerIdentifier)) {
        return Err(invalidVcdmIdentifier("issuer must be a URI"))
    }
    val iss = payload["iss"]?.let { stringClaim(it, "iss").getOrElse { return Err(it) } }
    if (iss != null && issuerIdentifier != iss) {
        return Err(inconsistentJwtClaim("iss must agree with issuer"))
    }
    if (iss != null && issuerIdentifier == null) {
        return Err(inconsistentJwtClaim("iss requires a matching issuer"))
    }

    val id = payload["id"]?.let { stringClaim(it, "id").getOrElse { return Err(it) } }
    if (id != null && !VcdmUris.isValid(id)) {
        return Err(invalidVcdmIdentifier("id must be a URI"))
    }
    val jti = payload["jti"]?.let { stringClaim(it, "jti").getOrElse { return Err(it) } }
    if (jti != null && id != jti) {
        return Err(inconsistentJwtClaim("jti must agree with id"))
    }

    if (!payload.containsKey("credentialSubject")) {
        return Err(invalidVcdm("credentialSubject is required"))
    }
    val subjectIds = credentialSubjectIds(payload["credentialSubject"]).getOrElse { return Err(it) }
    val sub = payload["sub"]?.let { stringClaim(it, "sub").getOrElse { return Err(it) } }
    if (sub != null) {
        if (subjectIds.size != 1) {
            return Err(inconsistentJwtClaim("sub is only applicable to one unambiguous credentialSubject.id"))
        }
        if (subjectIds.single() != sub) {
            return Err(inconsistentJwtClaim("sub must agree with credentialSubject.id"))
        }
    }
    return Ok(Unit)
}

private fun stringClaim(
    element: JsonElement,
    name: String,
): IdkResult<String, IdkError> {
    val primitive = element as? JsonPrimitive
    return if (primitive != null && primitive.isString) {
        Ok(primitive.content)
    } else {
        Err(invalidJwtClaim("$name must be a string"))
    }
}

private fun extractIssuerId(element: JsonElement): String? =
    when (element) {
        is JsonPrimitive -> element.takeIf { it.isString }?.content
        is JsonObject ->
            (element["id"] as? JsonPrimitive)?.takeIf { it.isString }?.content
        else -> null
    }

private fun credentialSubjectIds(element: JsonElement?): IdkResult<List<String>, IdkError> {
    val subjects =
        when (element) {
            null -> emptyList()
            is JsonObject -> listOf(element)
            is JsonArray -> element.map {
                it as? JsonObject
                    ?: return Err(inconsistentJwtClaim("credentialSubject entries must be objects"))
            }
            else -> return Err(inconsistentJwtClaim("credentialSubject must be an object or array"))
        }
    if (subjects.isEmpty()) {
        return Err(invalidVcdm("credentialSubject must contain at least one subject of claims"))
    }
    val ids = mutableListOf<String>()
    for (subject in subjects) {
        if (subject.isEmpty()) {
            return Err(invalidVcdm("credentialSubject entries must not be empty"))
        }
        val id = subject["id"] ?: continue
        val primitive = id as? JsonPrimitive
        if (primitive == null || !primitive.isString) {
            return Err(inconsistentJwtClaim("credentialSubject.id must be a string"))
        }
        if (!VcdmUris.isValid(primitive.content)) {
            return Err(invalidVcdmIdentifier("credentialSubject.id must be a URI"))
        }
        ids += primitive.content
    }
    // A subject claim is unambiguous only for exactly one subject object with exactly one id.
    return if (subjects.size == 1 && ids.size == 1) Ok(ids) else Ok(emptyList())
}

private fun invalidVcdm(message: String): IdkError =
    IdkError.fromString(code = "invalid_vcdm_credential", message = message)

private fun invalidJwtClaim(message: String): IdkError =
    IdkError.fromString(code = "invalid_jwt_claim", message = message)

private fun inconsistentJwtClaim(message: String): IdkError =
    IdkError.fromString(code = "inconsistent_jwt_claim", message = message)

private fun invalidVcdmIdentifier(message: String): IdkError =
    IdkError.fromString(code = "invalid_vcdm_identifier", message = message)
