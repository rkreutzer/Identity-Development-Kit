/*
 * Copyright 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

package com.sphereon.wallet.interaction.protocol.oid4vci

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.decodeFromBase64Url
import com.sphereon.core.api.error.IdkError
import com.sphereon.cbor.tDateToEpochSeconds
import com.sphereon.crypto.jose.jws.JwsUtils
import com.sphereon.crypto.jose.jws.JwsCompact
import com.sphereon.crypto.jose.jws.command.VerifyJwsArgs
import com.sphereon.crypto.jose.jws.command.VerifyJwsCommand
import com.sphereon.data.store.party.model.IdentityRole
import com.sphereon.data.store.party.model.IdentifierType
import com.sphereon.mdoc.data.device.IssuerSignedCborCodec
import com.sphereon.mdoc.data.device.IssuerSignedCborCodecImpl
import com.sphereon.mdoc.data.mso.MobileSecurityObject
import com.sphereon.mdoc.data.mso.MobileSecurityObjectCborCodec
import com.sphereon.mdoc.data.mso.MobileSecurityObjectCborCodecImpl
import com.sphereon.openid.oid4vc.common.vcdm.VcdmClassifier
import com.sphereon.openid.oid4vc.common.vcdm.VcdmDocumentKind
import com.sphereon.openid.oid4vc.common.vcdm.VcdmClassification
import com.sphereon.openid.oid4vc.common.vcdm.VcdmProfiles
import com.sphereon.openid.oid4vc.common.vcdm.VcdmVersion
import com.sphereon.openid.oid4vp.verifier.VcdmDataIntegrityVerificationArgs
import com.sphereon.openid.oid4vp.verifier.VcdmDataIntegrityVerifier
import com.sphereon.sdjwt.SdJwtCodec
import com.sphereon.sdjwt.vc.IssuerMetadataResolutionError
import com.sphereon.sdjwt.vc.IssuerMetadataResolutionResult
import com.sphereon.sdjwt.vc.IssuerMetadataResolver
import com.sphereon.sdjwt.vc.SdJwtVcClaims
import com.sphereon.sdjwt.vc.SdJwtVcVerificationOpts
import com.sphereon.sdjwt.vc.VerifySdJwtVcArgs
import com.sphereon.sdjwt.vc.command.VerifySdJwtVcCommand
import com.sphereon.wallet.WalletIdentityResolver
import com.sphereon.wallet.interaction.WalletIssuerAuthenticationResult
import com.sphereon.wallet.interaction.admitForIssuer
import com.sphereon.wallet.credential.CredentialFormat
import com.sphereon.wallet.credential.CredentialInstance
import com.sphereon.wallet.credential.CredentialSubjectExtractor
import com.sphereon.wallet.credential.CredentialTypeRef
import com.sphereon.wallet.credential.CredentialTypeRefKind
import com.sphereon.wallet.credential.CredentialTypeRefSource
import com.sphereon.wallet.credential.CredentialValidityWindow
import com.sphereon.wallet.credential.IdentifierRef
import com.sphereon.wallet.credential.IssuanceDiagnostic
import com.sphereon.wallet.credential.IssuanceDiagnosticCode
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive
import kotlin.time.Instant

private val acceptanceIssuerSignedCborCodec: IssuerSignedCborCodec = IssuerSignedCborCodecImpl()
private val acceptanceMobileSecurityObjectCborCodec: MobileSecurityObjectCborCodec = MobileSecurityObjectCborCodecImpl()

/**
 * Receive-time verification must stay hermetic with respect to the issuer: signature,
 * disclosure-integrity, and typ/vct checks all work from the credential itself, while the
 * best-effort `/.well-known/jwt-vc-issuer` metadata fetch is an OUTBOUND trust lookup that
 * belongs to the flow's trust-review stage (which has already run by the time the receiver
 * stores). The OIDF conformance suite enforces this: an issuance test is interrupted with
 * "unexpected HTTP call to .well-known/jwt-vc-issuer" if the wallet phones back mid-issuance.
 */
private object ReceiveTimeNoFetchIssuerMetadataResolver : IssuerMetadataResolver {
    override suspend fun resolve(issuer: String): IssuerMetadataResolutionResult =
        IssuerMetadataResolutionResult.Failure(
            IssuerMetadataResolutionError.NetworkError(
                message = "Issuer metadata resolution is deliberately skipped during receive-time acceptance",
            ),
        )

    override fun supports(issuer: String): Boolean = true
}

/**
 * Storage-side acceptance checks the OID4VCI interaction-engine receiver runs on newly issued
 * credential instances before they are persisted, before `putCredential`.
 *
 * Three storage-side value-adds live here as a focused, independently testable collaborator
 * (rather than inlined into the receiver) so the receiver's `receiveCredentialResponse` stays
 * readable:
 *  1. VERIFY: issuer-signature verification of newly issued SD-JWT VC instances ([verify]).
 *  2. RECONCILE: actual (payload-derived) credential type-ref derivation, kept canonical on the
 *     record, reconciled against the issuer-metadata-derived expected refs with a mismatch
 *     diagnostic when they differ ([actualTypeRefs] / [diagnostics]).
 *  3. SUBJECTS: credential-subject extraction + identity resolution for newly created records
 *     ([resolveSubjects]).
 */
class Oid4vciIssuedCredentialAcceptance(
    private val verifySdJwtVcCommand: VerifySdJwtVcCommand,
    private val verifyJwsCommand: VerifyJwsCommand? = null,
    private val subjectExtractor: CredentialSubjectExtractor,
    private val identityResolvers: Set<WalletIdentityResolver>,
    /** Peer-aware DI verification seam; absent means ldp_vc receipt fails closed. */
    private val vcdmDataIntegrityVerifier: VcdmDataIntegrityVerifier? = null,
) {
    constructor(
        verifySdJwtVcCommand: VerifySdJwtVcCommand,
        verifyJwsCommand: VerifyJwsCommand? = null,
        subjectExtractor: CredentialSubjectExtractor,
        identityResolver: WalletIdentityResolver,
        vcdmDataIntegrityVerifier: VcdmDataIntegrityVerifier? = null,
    ) : this(
        verifySdJwtVcCommand = verifySdJwtVcCommand,
        verifyJwsCommand = verifyJwsCommand,
        subjectExtractor = subjectExtractor,
        identityResolvers = setOf(identityResolver),
        vcdmDataIntegrityVerifier = vcdmDataIntegrityVerifier,
    )
    /**
     * VERIFY: for SD-JWT VC formats, runs [VerifySdJwtVcCommand] per instance; a failed
     * verification rejects the whole store operation. Non-SD-JWT formats are not gated.
     */
    suspend fun verify(
        credentialConfigurationId: String,
        credentialFormat: CredentialFormat,
        instances: List<CredentialInstance>,
        issuerAuthentication: WalletIssuerAuthenticationResult? = null,
        expectedIssuer: String? = null,
    ): IdkResult<Unit, IdkError> {
        if (credentialFormat == CredentialFormat.LDP_VC) {
            return verifyLdpVc(
                credentialConfigurationId = credentialConfigurationId,
                instances = instances,
                expectedIssuer = expectedIssuer,
            )
        }
        if (credentialFormat.isJwtVc()) {
            val suppliedAuthentication = issuerAuthentication ?: return verificationFailure(
                credentialConfigurationId,
                IssuedCredentialVerificationReason.ISSUER_KEYS_MISSING, "issuer authentication keys are unavailable",
            )
            val authentication = suppliedAuthentication.admitForIssuer(suppliedAuthentication.issuer)
                ?: return verificationFailure(credentialConfigurationId, IssuedCredentialVerificationReason.ISSUER_AUTHENTICATION_REFUSED, "issuer authentication admission failed")
            if (expectedIssuer != null && authentication.issuer != expectedIssuer) {
                return verificationFailure(
                    credentialConfigurationId,
                    IssuedCredentialVerificationReason.ISSUER_AUTHENTICATION_MISMATCH, "resolved issuer authentication is not bound to the credential issuer",
                )
            }
            val verifier = verifyJwsCommand ?: return verificationFailure(
                credentialConfigurationId,
                IssuedCredentialVerificationReason.JWS_COMMAND_MISSING, "JWS verification command is unavailable",
            )
            for (instance in instances) {
                val raw = instance.requireRaw()
                val classification = acceptedVcdmCredential(credentialFormat, raw)
                    ?: return verificationFailure(credentialConfigurationId, IssuedCredentialVerificationReason.CREDENTIAL_PROFILE_MISMATCH, "credential does not match its VCDM profile")
                val verifyResult = verifier.execute(
                    VerifyJwsArgs(
                        jws = JwsCompact(raw),
                        trustedJwks = authentication.trustedJwks,
                    ),
                )
                if (verifyResult.isErr) {
                    return verificationFailure(credentialConfigurationId, IssuedCredentialVerificationReason.JWS_COMMAND_FAILED,
                        "issuer JWS verification failed", verifyResult.error)
                }
                val verified = verifyResult.value
                val refusal = when {
                    !verified.isValid -> IssuedCredentialVerificationReason.JWS_INVALID
                    !verified.trustEstablished -> IssuedCredentialVerificationReason.JWS_UNTRUSTED
                    verified.cryptoVerified != true -> IssuedCredentialVerificationReason.JWS_CRYPTO_UNVERIFIED
                    else -> null
                }
                if (refusal != null) {
                    return verificationFailure(credentialConfigurationId, refusal, "issuer JWS verification failed")
                }
                val verifiedPayload = verifyResult.value.parsedPayload
                val verifiedDocument = if (classification.document.version.value == "1.1") {
                    verifiedPayload["vc"] as? JsonObject
                } else {
                    verifiedPayload
                }
                val credentialIssuer = verifiedDocument?.get("issuer")?.issuerIdentifier()
                val jwtIssuer = verifiedPayload["iss"]?.stringValue()
                if (credentialIssuer == null || credentialIssuer != authentication.issuer ||
                    (jwtIssuer != null && jwtIssuer != authentication.issuer)
                ) {
                    return verificationFailure(credentialConfigurationId, IssuedCredentialVerificationReason.CREDENTIAL_ISSUER_MISMATCH, "credential issuer does not match resolved issuer authentication")
                }
            }
            return Ok(Unit)
        }
        if (!credentialFormat.isSdJwt) return Ok(Unit)
        for (instance in instances) {
            val verifyResult =
                verifySdJwtVcCommand.execute(
                    VerifySdJwtVcArgs(
                        sdJwt = instance.requireRaw(),
                        opts =
                            SdJwtVcVerificationOpts(
                                validateTypeMetadata = false,
                                validateStatus = false,
                                issuerMetadataResolver = ReceiveTimeNoFetchIssuerMetadataResolver,
                            ),
                    ),
                )
            if (verifyResult.isErr) {
                return Err(
                    IssuedCredentialVerificationError(
                        reason = IssuedCredentialVerificationReason.SD_JWT_VERIFICATION_FAILED,
                        credentialConfigurationId = credentialConfigurationId,
                        description = "issuer-signature verification failed: ${verifyResult.error.message.defaultMessage}",
                        providerError = verifyResult.error,
                    ),
                )
            }
        }
        return Ok(Unit)
    }

    private suspend fun verifyLdpVc(
        credentialConfigurationId: String,
        instances: List<CredentialInstance>,
        expectedIssuer: String?,
    ): IdkResult<Unit, IdkError> {
        val verifier = vcdmDataIntegrityVerifier
            ?: return verificationFailure(credentialConfigurationId, IssuedCredentialVerificationReason.DATA_INTEGRITY_VERIFIER_MISSING, "Data Integrity verifier is unavailable")
        for (instance in instances) {
            val document = parseBareVcdm(instance.requireRaw())
                ?: return verificationFailure(credentialConfigurationId, IssuedCredentialVerificationReason.LDP_DOCUMENT_MALFORMED, "ldp_vc credential is not a JSON object")
            val classification = VcdmClassifier.classifyDocument(document).getOrNull()
                ?: return verificationFailure(credentialConfigurationId, IssuedCredentialVerificationReason.LDP_PROFILE_UNSUPPORTED, "ldp_vc credential is not a supported VCDM JSON document")
            if (classification.kind != VcdmDocumentKind.CREDENTIAL) {
                return verificationFailure(credentialConfigurationId, IssuedCredentialVerificationReason.LDP_NOT_CREDENTIAL, "ldp_vc credential is not a VerifiableCredential")
            }
            val issuer = document["issuer"]?.issuerIdentifier()
                ?: return verificationFailure(credentialConfigurationId, IssuedCredentialVerificationReason.LDP_ISSUER_MISSING, "ldp_vc credential issuer is missing")
            if (expectedIssuer != null && issuer != expectedIssuer) {
                return verificationFailure(credentialConfigurationId, IssuedCredentialVerificationReason.LDP_ISSUER_MISMATCH, "ldp_vc credential issuer does not match the resolved issuer")
            }
            val verified = verifier.verify(
                VcdmDataIntegrityVerificationArgs(
                    document = document,
                    expectedProofPurpose = com.sphereon.crypto.dataintegrity.model.ProofPurpose.ASSERTION_METHOD,
                    expectedController = issuer,
                ),
            )
            val unsecuredDocument = JsonObject(document - "proof")
            if (verified.isErr || verified.value.proofCount < 1 || verified.value.verifiedDocument != unsecuredDocument) {
                return verificationFailure(credentialConfigurationId, IssuedCredentialVerificationReason.DATA_INTEGRITY_VERIFICATION_FAILED, "ldp_vc Data Integrity verification failed", if (verified.isErr) verified.error else null)
            }
        }
        return Ok(Unit)
    }

    private fun verificationFailure(
        credentialConfigurationId: String,
        reason: IssuedCredentialVerificationReason,
        description: String,
        providerError: IdkError? = null,
    ): IdkResult<Unit, IdkError> =
        Err(IssuedCredentialVerificationError(reason, credentialConfigurationId, description, providerError))

    /**
     * RECONCILE (actual side): derives ACTUAL type refs from each issued payload (vct / docType /
     * W3C types per format). Issued credentials with NO derivable payload type refs are rejected.
     */
    fun actualTypeRefs(
        credentialConfigurationId: String,
        credentialFormat: CredentialFormat,
        instances: List<CredentialInstance>,
    ): IdkResult<Set<CredentialTypeRef>, IdkError> {
        val actual = mutableSetOf<CredentialTypeRef>()
        for (instance in instances) {
            val instanceRefs = credentialPayloadTypeRefs(credentialFormat, instance.requireRaw())
            if (instanceRefs.isEmpty()) {
                return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message =
                            "No credentialTypeRefs could be derived from issued credential payload '${instance.id}' " +
                                "for '$credentialConfigurationId'",
                    ),
                )
            }
            actual += instanceRefs
        }
        return Ok(actual)
    }

    /**
     * RECONCILE (diagnostic side): expected (issuer-metadata) refs stay canonical on the record;
     * a mismatch against the actual refs appends a diagnostic, including the empty-expected
     * short-circuit (an issuer that declares no type constraints cannot mismatch).
     */
    fun diagnostics(
        expected: Set<CredentialTypeRef>,
        actual: Set<CredentialTypeRef>,
        observedAt: Instant,
    ): List<IssuanceDiagnostic> {
        if (expected.isEmpty()) return emptyList()
        if (expected.referenceKeys() == actual.referenceKeys()) return emptyList()
        return listOf(
            IssuanceDiagnostic(
                code = IssuanceDiagnosticCode.CREDENTIAL_TYPE_REF_MISMATCH,
                message = "Issued credential type references differ from issuer metadata expectations",
                expectedCredentialTypeRefs = expected,
                actualCredentialTypeRefs = actual,
                observedAt = observedAt,
            ),
        )
    }

    /**
     * SUBJECTS: extracts subject identifiers from an issued instance's raw payload and resolves
     * each through the identity book (extractSubjects + identityResolver.resolve(...,
     * IdentityRole.HOLDER) per subject). Callers populate this only once, when a NEW record is
     * created - existing records are not re-populated on append.
     */
    suspend fun resolveSubjects(
        credentialFormat: CredentialFormat,
        raw: String,
    ): IdkResult<List<IdentifierRef>, IdkError> {
        if (credentialFormat.isJwtVc() && acceptedVcdmCredential(credentialFormat, raw) == null) {
            return Err(
                IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message = "Issued compact-JWS credential does not match its VCDM profile",
                ),
            )
        }
        val extracted =
            if (credentialFormat == CredentialFormat.LDP_VC) {
                val document = parseBareVcdm(raw) ?: return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Issued ldp_vc credential is not a JSON object"),
                )
                val classification = VcdmClassifier.classifyDocument(document).getOrNull() ?: return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Issued ldp_vc credential does not match a supported VCDM profile"),
                )
                if (classification.kind != VcdmDocumentKind.CREDENTIAL) return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Issued ldp_vc credential is not a VerifiableCredential"),
                )
                bareCredentialSubjects(document)
            } else {
                subjectExtractor.extractSubjects(credentialFormat, raw)
            }
        if (extracted.isEmpty()) return Ok(emptyList())
        val identityResolver =
            identityResolvers.singleOrNull()
                ?: return Err(
                    IdkError.INVALID_STATE(
                        message = "wallet_identity_resolver_unavailable",
                    ),
                )
        val resolved = mutableListOf<IdentifierRef>()
        for (subjectRef in extracted) {
            val resolvedResult = identityResolver.resolve(subjectRef, IdentityRole.HOLDER)
            if (resolvedResult.isErr) return Err(resolvedResult.error)
            resolved += resolvedResult.value
        }
        return Ok(resolved)
    }

    private fun credentialPayloadTypeRefs(
        format: CredentialFormat,
        raw: String,
    ): Set<CredentialTypeRef> =
        when {
            format.isSdJwt -> sdJwtVct(raw, format)
            format.isMdoc -> mdocDoctype(raw, format)
            format == CredentialFormat.LDP_VC -> w3cTypeRefsFromBareJson(raw, format)
            format.isJwt || format == CredentialFormat.JWT_VC_JSON_LD -> w3cTypeRefsFromPayload(format, w3cTypesFromJwt(format, raw))
            else -> emptySet()
        }

    private fun sdJwtVct(
        raw: String,
        format: CredentialFormat,
    ): Set<CredentialTypeRef> {
        val parseResult = SdJwtCodec.parse(raw)
        if (parseResult.isErr) return emptySet()
        val vct = SdJwtVcClaims.vct(parseResult.value.payload.fullPayload) ?: return emptySet()
        return setOf(
            CredentialTypeRef(
                format = format,
                kind = CredentialTypeRefKind.SD_JWT_VCT,
                value = vct,
                source = CredentialTypeRefSource.CREDENTIAL_PAYLOAD,
                primary = true,
            ),
        )
    }

    private fun mdocDoctype(
        raw: String,
        format: CredentialFormat,
    ): Set<CredentialTypeRef> {
        val mso = decodeMdocMso(raw) ?: return emptySet()
        val doctype =
            mso.docType
                .toString()
                .takeIf { it.isNotBlank() } ?: return emptySet()
        return setOf(
            CredentialTypeRef(
                format = format,
                kind = CredentialTypeRefKind.MDOC_DOCTYPE,
                value = doctype,
                source = CredentialTypeRefSource.CREDENTIAL_PAYLOAD,
                primary = true,
            ),
        )
    }

    /**
     * Returns the validity window carried by an mdoc's MSO using the existing IssuerSigned/MSO
     * codecs. A missing or malformed MSO is not stored with an UNKNOWN validity window.
     */
    internal fun mdocValidityWindow(raw: String): CredentialValidityWindow? {
        val validityInfo = decodeMdocMso(raw)?.validityInfo ?: return null
        return CredentialValidityWindow(
            validFrom = Instant.fromEpochSeconds(validityInfo.validFrom.tDateToEpochSeconds()),
            validUntil = Instant.fromEpochSeconds(validityInfo.validUntil.tDateToEpochSeconds()),
        )
    }

    private fun decodeMdocMso(raw: String): MobileSecurityObject? {
        return try {
            val issuerSignedBytes = raw.decodeFromBase64Url()
            val issuerSigned = acceptanceIssuerSignedCborCodec.decode(issuerSignedBytes).getOrNull()?.value
                ?: return null
            val msoPayload = issuerSigned.issuerAuth.payload?.value ?: return null
            acceptanceMobileSecurityObjectCborCodec.decode(msoPayload).getOrNull()?.value
        } catch (_: Exception) {
            null
        }
    }

    private fun w3cTypesFromJwt(
        format: CredentialFormat,
        raw: String,
    ): List<String> {
        // Compact-JWS VCDM credentials have two deliberately distinct wire profiles:
        // VCDM 1.1 uses a `vc` wrapper, while VCDM 2.0 carries the credential at the
        // payload root. Use the shared classifier as the acceptance boundary so a
        // structurally plausible but wrong-version shape (including alg:none) cannot
        // be stored merely because it contains a `type` claim.
        if (format == CredentialFormat.JWT_VC_JSON || format == CredentialFormat.JWT_VC_JSON_LD) {
            val classification = acceptedVcdmCredential(format, raw) ?: return emptyList()
            return jsonStringList(classification.document.json["type"])
        }

        val parts = raw.split(".")
        if (parts.size < 2) return emptyList()
        return try {
            val payload = JwsUtils.decodeBase64UrlToJson(parts[1])
            val vcClaim = payload["vc"]
            if (vcClaim is JsonObject) {
                val vcTypes = jsonStringList(vcClaim["type"])
                if (vcTypes.isNotEmpty()) return vcTypes
            }
            jsonStringList(payload["type"])
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun w3cTypeRefsFromPayload(
        format: CredentialFormat,
        types: List<String>,
    ): Set<CredentialTypeRef> {
        val cleanTypes = types.map { it.trim() }.filter { it.isNotBlank() }.distinct()
        val primaryType = cleanTypes.firstOrNull { it != "VerifiableCredential" } ?: cleanTypes.firstOrNull()
        return cleanTypes
            .map {
                CredentialTypeRef(
                    format = format,
                    kind = CredentialTypeRefKind.W3C_VC_TYPE,
                    value = it,
                    source = CredentialTypeRefSource.CREDENTIAL_PAYLOAD,
                    primary = it == primaryType,
                )
            }.toSet()
    }

    private fun w3cTypeRefsFromBareJson(
        raw: String,
        format: CredentialFormat,
    ): Set<CredentialTypeRef> {
        val document = parseBareVcdm(raw) ?: return emptySet()
        val classification = VcdmClassifier.classifyDocument(document).getOrNull() ?: return emptySet()
        if (classification.kind != VcdmDocumentKind.CREDENTIAL) return emptySet()
        return w3cTypeRefsFromPayload(format, jsonStringList(classification.json["type"]))
    }

    private fun parseBareVcdm(raw: String): JsonObject? =
        runCatching { kotlinx.serialization.json.Json.parseToJsonElement(raw) as? JsonObject }.getOrNull()

    private fun bareCredentialSubjects(document: JsonObject): List<IdentifierRef> {
        val subject = document["credentialSubject"] ?: return emptyList()
        val values = when (subject) {
            is JsonObject -> listOf(subject)
            is JsonArray -> subject.mapNotNull { it as? JsonObject }
            else -> emptyList()
        }
        return values.mapNotNull { value ->
            val id = value["id"]?.jsonPrimitive?.contentOrNull?.takeIf { it.isNotBlank() } ?: return@mapNotNull null
            IdentifierRef(
                type = if (id.startsWith("did:")) IdentifierType.DID else IdentifierType("uri"),
                value = id,
            )
        }
    }

    private fun jsonStringList(element: JsonElement?): List<String> =
        when (element) {
            is JsonArray -> element.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }
            is JsonPrimitive -> element.contentOrNull?.let { listOf(it) }.orEmpty()
            else -> emptyList()
        }

    private fun CredentialFormat.isJwtVc(): Boolean =
        this == CredentialFormat.JWT_VC_JSON || this == CredentialFormat.JWT_VC_JSON_LD

    /**
     * The single issuer identifier claimed by newly issued VCDM JWT instances, before verification.
     * It only selects where issuer keys are resolved (OID4VCI 1.0 §14.4: a DID-signed credential
     * names its DID, not the Credential Issuer URL); [verify] still binds the verified claim to the
     * resolved authentication. Null for other formats, malformed payloads, or differing issuers.
     */
    fun claimedJwtVcIssuer(
        credentialFormat: CredentialFormat,
        instances: List<CredentialInstance>,
    ): String? {
        if (!credentialFormat.isJwtVc() || instances.isEmpty()) return null
        return instances.map { instance ->
            acceptedVcdmCredential(credentialFormat, instance.requireRaw())
                ?.document?.json?.get("issuer")?.issuerIdentifier()
                ?: return null
        }.distinct().singleOrNull()
    }

    private fun acceptedVcdmCredential(
        format: CredentialFormat,
        raw: String,
    ): VcdmClassification? {
        if (!format.isJwtVc()) return null
        val classification = VcdmClassifier.classifyCompactJws(raw).getOrNull() ?: return null
        if (classification.document.kind != VcdmDocumentKind.CREDENTIAL || classification.credentialFormat != format) return null
        val profileValidation =
            when (classification.document.version) {
                VcdmVersion.V1_1 -> VcdmProfiles.v1_1.validateCredential(classification.document.json)
                VcdmVersion.V2_0 -> VcdmProfiles.v2_0.validateCredential(classification.document.json)
                else -> return null
            }
        if (!profileValidation.valid) return null
        return classification
    }

    private fun Set<CredentialTypeRef>.referenceKeys(): Set<Triple<CredentialFormat, CredentialTypeRefKind, String>> = map { Triple(it.format, it.kind, it.value) }.toSet()
}

private fun JsonElement.stringValue(): String? =
    (this as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull?.takeIf { it.isNotBlank() }

private fun JsonElement.issuerIdentifier(): String? =
    when (this) {
        is JsonPrimitive -> stringValue()
        is JsonObject -> this["id"]?.stringValue()
        else -> null
    }
