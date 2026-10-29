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

package com.sphereon.openid.oid4vp.verifier.impl

import com.sphereon.cbor.CborParser
import com.sphereon.core.api.Encoding
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Err
import com.sphereon.core.api.Ok
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.decodeFromBase64Url
import com.sphereon.core.api.encodeTo
import com.sphereon.core.api.encodeToBase64Url
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.events.EventCategories
import com.sphereon.core.api.events.EventSubsystems
import com.sphereon.core.api.events.EventTypes
import com.sphereon.core.api.service.TypedServiceCommandAdapter
import com.sphereon.core.events.SessionEventService
import com.sphereon.crypto.jose.jws.JwsCompact
import com.sphereon.crypto.core.generic.DigestAlg
import com.sphereon.crypto.core.generic.hash
import com.sphereon.crypto.jose.jws.command.VerifyJwsArgs
import com.sphereon.crypto.jose.jws.command.VerifyJwsCommand
import com.sphereon.crypto.dataintegrity.model.ProofPurpose
import com.sphereon.crypto.dataintegrity.resolution.VerificationMethodResolutionPolicy
import com.sphereon.crypto.resolution.IdentifierMethodDefaults
import com.sphereon.crypto.resolution.extern.ExternalIdentifierDidOpts
import com.sphereon.di.session.SessionScope
import com.sphereon.jsonld.JsonLdError
import com.sphereon.jsonld.WellKnownContexts
import com.sphereon.jsonld.WellKnownCredentialTypes
import com.sphereon.jsonld.command.JsonLdContextValidator
import com.sphereon.jsonld.command.JsonLdSchemaValidator
import com.sphereon.jsonld.command.ValidateJsonLdContextInput
import com.sphereon.jsonld.command.ValidateJsonLdSchemaInput
import com.sphereon.mdoc.data.device.DeviceResponseCborCodec
import com.sphereon.mdoc.data.mso.MobileSecurityObjectCborCodec
import com.sphereon.oauth2.common.model.AuthorizationRequest
import com.sphereon.openid.oid4vp.common.CredentialFormat
import com.sphereon.openid.oid4vp.common.ResponseMode
import com.sphereon.openid.oid4vp.dcql.DcqlCredentialQuery
import com.sphereon.openid.oid4vp.common.clientMetadata
import com.sphereon.openid.oid4vp.common.responseUri
import com.sphereon.openid.oid4vc.common.vcdm.VcdmClassifier
import com.sphereon.openid.oid4vc.common.vcdm.VcdmClassification
import com.sphereon.openid.oid4vc.common.vcdm.VcdmDocumentKind
import com.sphereon.openid.oid4vc.common.vcdm.VcdmProfiles
import com.sphereon.openid.oid4vc.common.vcdm.VcdmUris
import com.sphereon.openid.oid4vc.common.vcdm.VcdmVersion
import com.sphereon.openid.oid4vc.common.PresentationFormat
import com.sphereon.openid.oid4vp.verifier.CredentialIssuerRef
import com.sphereon.openid.oid4vp.verifier.CredentialIssuerControllerClaim
import com.sphereon.openid.oid4vp.verifier.CredentialTypeMatcher
import com.sphereon.sdjwt.vc.SdJwtVcClaims
import com.sphereon.openid.oid4vp.verifier.CredentialTrustValidation
import com.sphereon.openid.oid4vp.verifier.CredentialTrustValidationMode
import com.sphereon.openid.oid4vp.verifier.TrustedAuthenticationResolution
import com.sphereon.crypto.resolution.extern.ExternalIdentifierX5cOpts
import com.sphereon.openid.oid4vp.verifier.TrustedAuthenticationPurpose
import com.sphereon.openid.oid4vp.verifier.MatchedCredential
import com.sphereon.openid.oid4vp.verifier.VerifiedCredentialTemporalFacts
import com.sphereon.openid.oid4vp.verifier.VerifiedCredentialEvidence
import com.sphereon.openid.oid4vp.verifier.VerifiedCredentialStatus
import com.sphereon.openid.oid4vp.verifier.VerifiedCredentialStatusOutcome
import com.sphereon.openid.oid4vp.verifier.Oid4vpCredentialTrustValidationArgs
import com.sphereon.openid.oid4vp.verifier.CredentialValidationRejection
import com.sphereon.openid.oid4vp.verifier.CredentialValidationRejectionReason
import com.sphereon.openid.oid4vp.verifier.Oid4vpCredentialTrustValidator
import com.sphereon.openid.oid4vp.verifier.ValidateAuthorizationResponseArgs
import com.sphereon.openid.oid4vp.verifier.ValidateAuthorizationResponseCommand
import com.sphereon.openid.oid4vp.verifier.ValidateAuthorizationResponseCommandService
import com.sphereon.openid.oid4vp.verifier.ValidationResult
import com.sphereon.openid.oid4vp.verifier.VcdmDataIntegrityVerificationArgs
import com.sphereon.openid.oid4vp.verifier.VcdmDataIntegrityVerifier
import com.sphereon.openid.oid4vp.verifier.VerifyHolderBindingArgs
import com.sphereon.openid.oid4vp.verifier.VerifyHolderBindingCommand
import com.sphereon.openid.oid4vp.verifier.impl.event.emitOid4vpSessionHistoryEvent
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSession
import com.sphereon.openid.oid4vp.verifier.store.AuthorizationSessionStore
import com.sphereon.sdjwt.SdJwtCodec
import com.sphereon.statuslist.CredentialStatusDecision
import com.sphereon.statuslist.CredentialStatusEvaluation
import com.sphereon.statuslist.CredentialStatusInput
import com.sphereon.statuslist.CredentialStatusMetadata
import com.sphereon.statuslist.CredentialStatusPolicy
import com.sphereon.statuslist.CredentialStatusReference
import com.sphereon.statuslist.MdocCredentialStatusMetadata
import com.sphereon.statuslist.StatusPurpose
import com.sphereon.statuslist.StatusValues
import com.sphereon.statuslist.describeStatus
import com.sphereon.statuslist.evaluateCredentialStatus
import com.sphereon.statuslist.spi.CredentialStatusVerifier
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put
import kotlin.time.Clock
import kotlin.time.Instant

import dev.zacsweers.metro.ExposeImplBinding

/** Appendix A.4 binds a DC API presentation to the browser Origin, even for a signed request. */
internal fun holderBindingClientId(request: AuthorizationRequest): String? {
    if (request.responseMode != ResponseMode.DC_API.value && request.responseMode != ResponseMode.DC_API_JWT.value) {
        return request.clientId
    }
    val origins = request.additionalParameters?.get("expected_origins") as? JsonArray ?: return null
    if (origins.size != 1) return null
    val origin = (origins.single() as? JsonPrimitive)?.contentOrNull ?: return null
    if (!origin.matches(Regex("^https?://[^/?#@\\s]+$"))) return null
    return "origin:$origin"
}

/**
 * Implementation of ValidateAuthorizationResponseCommand for OpenID4VP RP (Verifier).
 *
 * Validates authorization responses against the original DCQL query:
 * - Validates state parameter matches original request
 * - Validates VP token format matches requested formats
 * - Validates credentials satisfy DCQL query requirements
 * - Validates required claims are present
 *
 * OpenID4VP 1.0 Final:
 * - VP tokens are self-descriptive (format is determined from the token itself)
 * - NO presentation_submission validation (that's DIF PE, not used in OID4VP 1.0 Final)
 *
 * Reference: OpenID4VP 1.0 Final Section 7 - Verifiable Presentation Validation
 */
@Inject
@SingleIn(SessionScope::class)
@ExposeImplBinding
class ValidateAuthorizationResponseCommandImpl(
    execution: SessionExecution,
    private val authorizationSessionStore: AuthorizationSessionStore,
    private val verifyHolderBindingCommand: VerifyHolderBindingCommand,
    private val verifyJwsCommand: VerifyJwsCommand,
    private val jsonLdContextValidator: JsonLdContextValidator,
    private val jsonLdSchemaValidator: JsonLdSchemaValidator,
    private val deviceResponseCborCodec: DeviceResponseCborCodec,
    private val mobileSecurityObjectCborCodec: MobileSecurityObjectCborCodec,
    private val cborParser: CborParser,
    private val vcdmDataIntegrityVerifier: VcdmDataIntegrityVerifier,
    /**
     * Optional, possibly-empty set of credential-status mechanisms. Populated only when status-list
     * implementations (e.g. `lib-statuslist-impl`) are on the verifier's classpath. Empty ⇒ no status
     * checking runs at all; non-empty ⇒ each matched credential is evaluated against its per-query
     * [CredentialStatusPolicy]. The set is declared `allowEmpty` by `CredentialStatusVerifierMultibinds`
     * in lib-statuslist-public, so the graph resolves even with zero implementations.
     */
    private val credentialStatusVerifiers: Set<CredentialStatusVerifier>,
    /**
     * Optional, possibly-empty set of OID4VP credential-trust validators. No default: a defaulted
     * `Set<T>` constructor parameter is silently skipped by Metro codegen (the binding is never
     * resolved and the default is always used), which would make this always resolve to an empty
     * set regardless of what is actually contributed - defeating the R3 fail-closed trust-domain
     * validator. The set is declared `allowEmpty` by `Oid4vpCredentialTrustValidatorMultibinds` in
     * lib-openid-oid4vp-verifier-public (mirrors `credentialStatusVerifiers`/
     * `CredentialStatusVerifierMultibinds` above), so the graph still resolves with zero
     * implementations when no trust validator is contributed.
     */
    private val credentialTrustValidators: Set<Oid4vpCredentialTrustValidator>,
    private val businessAuthorizations: Set<com.sphereon.openid.oid4vp.verifier.Oid4vpBusinessAuthorization>,
    private val credentialTypeMatcher: CredentialTypeMatcher,
    private val eventService: SessionEventService? = null,
) : TypedServiceCommandAdapter<ValidateAuthorizationResponseArgs, ValidationResult, IdkError>(
        commandId = ValidateAuthorizationResponseCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<ValidateAuthorizationResponseArgs>(),
        outputTypeToken = typeToken<ValidationResult>(),
    ),
    ValidateAuthorizationResponseCommand,
    ValidateAuthorizationResponseCommandService {
    override val commandId: String get() = ValidateAuthorizationResponseCommand.COMMAND_ID
    private var pendingHistorySession: AuthorizationSession? = null

    override suspend fun supports(args: Any): Boolean = args is ValidateAuthorizationResponseArgs

    override suspend fun validateAuthorizationResponse(args: ValidateAuthorizationResponseArgs): IdkResult<ValidationResult, IdkError> = execute(args)

    override suspend fun doExecute(
        args: ValidateAuthorizationResponseArgs,
        applyDuring: (ValidateAuthorizationResponseArgs) -> ValidateAuthorizationResponseArgs,
    ): IdkResult<ValidationResult, IdkError> {
        val correlationId =
            (args.sessionCorrelationId ?: args.originalRequest.state)?.takeIf(String::isNotBlank)
                ?: return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message = "OID4VP authorization response has no session correlation state",
                    ),
                )
        pendingHistorySession =
            authorizationSessionStore.get(correlationId).getOrElse { return Err(it) }
                ?: return Err(
                    IdkError.NOT_FOUND_ERROR(
                        resource = "authorizationSession:$correlationId",
                        message = "OID4VP authorization session not found",
                    ),
                )
        try {
        val result = doExecuteInternal(args, applyDuring)
        // Record proof validity independently; a later business denial does not falsify this fact.
        emitOutcome(result)
        var businessAuthorizationError: IdkError? = null
        if (result.isOk && result.value.valid) {
            // An unset mode preserves the historical protocol-only verifier behavior. The
            // business-authorized path is opt-in through an explicit `required` (or `ordinary`)
            // deployment setting; `required` still fails closed when no authority is bound.
            val mode = execution.conf.app.getPropertyAsString("oid4vp.business-authorization.mode")
                ?.takeUnless { it.isBlank() }
            if (mode == "required" || mode == "ordinary") {
                val businessAuthorizationRequired = mode == "required"
                val authorization = com.sphereon.openid.oid4vp.verifier.authorizeVerifierBusinessAction(
                    businessAuthorizationRequired, pendingHistorySession, result.value, businessAuthorizations,
                )
                if (authorization.isErr) businessAuthorizationError = authorization.error
            }
        }
        val correlation = args.sessionCorrelationId ?: args.originalRequest.state
        if (!correlation.isNullOrBlank()) {
            val previousSession = pendingHistorySession
            pendingHistorySession = authorizationSessionStore.storeValidationResultDeferred(
                correlationId = correlation,
                validationResult = result.getOrElse { return Err(it) },
            ).getOrElse { return Err(it) }
            authorizationSessionStore.dispatchDeferredValidation(correlation, previousSession).getOrElse { return Err(it) }
        }
        businessAuthorizationError?.let { return Err(it) }
        return result
        } finally {
            pendingHistorySession = null
        }
    }

    /**
     * Emit the technical credential-status rejection detail (status list URI / index / value) as an
     * event for ops/audit. Deliberately separate from the short user-facing error so the URI and index
     * never leak into the verification result returned to the wallet/relying party UI.
     */
    private suspend fun emitStatusRejected(
        queryId: String,
        evaluation: CredentialStatusEvaluation,
    ) {
        val es = eventService ?: return
        val rejected = evaluation.rejectedStatus
        es.emit(
            es
                .eventBuilder()
                .type(EventTypes.OID4VP_CREDENTIAL_STATUS_REJECTED)
                .subsystem(EventSubsystems.OID4VP)
                .category(EventCategories.SECURITY)
                .origin(ValidateAuthorizationResponseCommand.COMMAND_ID)
                .payload(
                    buildJsonObject {
                        put("credentialQueryId", queryId)
                        rejected?.let {
                            put("statusValue", it.value)
                            put("status", describeStatus(it))
                            put("statusListUri", it.statusListUri)
                        }
                        evaluation.reason?.let { put("detail", it) }
                    },
                ).build(),
        )
    }

    /**
     * Map a status REJECT onto the typed rejection channel. Only the credential query identity, the
     * ground and the raw status value are carried; the status list URI and index stay in the event
     * emitted by [emitStatusRejected].
     *
     * Revocation and suspension are read structurally from the resolved status, in the same
     * precedence [describeStatus] uses: a declared status purpose wins over the raw value, which is
     * only interpreted with the canonical Token Status List meanings. A non-accepted value that
     * asserts neither - an issuer-defined multi-bit state admitted through
     * [CredentialStatusPolicy.acceptStatusValues] - is
     * [CredentialValidationRejectionReason.STATUS_NOT_ACCEPTED] with its raw value in `statusValue`,
     * never a revocation: the policy refused it, the status list did not revoke it.
     *
     * [CredentialStatusEvaluation.rejectedStatus] is null for both the required-but-absent and the
     * unresolvable rejection, and `evaluateCredentialStatus` separates them only by its technical
     * reason, so the unresolvable reason prefix is matched here.
     */
    private fun statusRejection(
        queryId: String,
        evaluation: CredentialStatusEvaluation,
    ): CredentialValidationRejection {
        val rejected = evaluation.rejectedStatus
        val reason =
            when {
                rejected == null ->
                    if (evaluation.reason?.startsWith(UNRESOLVABLE_STATUS_REASON_PREFIX) == true) {
                        CredentialValidationRejectionReason.STATUS_UNRESOLVABLE
                    } else {
                        CredentialValidationRejectionReason.STATUS_REQUIRED_BUT_ABSENT
                    }
                rejected.purpose == StatusPurpose.SUSPENSION -> CredentialValidationRejectionReason.SUSPENDED
                rejected.purpose == StatusPurpose.REVOCATION -> CredentialValidationRejectionReason.REVOKED
                rejected.purpose != null -> CredentialValidationRejectionReason.STATUS_NOT_ACCEPTED
                rejected.value == StatusValues.SUSPENDED -> CredentialValidationRejectionReason.SUSPENDED
                rejected.value == StatusValues.INVALID -> CredentialValidationRejectionReason.REVOKED
                else -> CredentialValidationRejectionReason.STATUS_NOT_ACCEPTED
            }
        return CredentialValidationRejection(
            credentialQueryId = queryId,
            reason = reason,
            checkedAtEpochMillis = Clock.System.now().toEpochMilliseconds(),
            statusValue = rejected?.value,
        )
    }

    private suspend fun emitOutcome(result: IdkResult<ValidationResult, IdkError>,) {
        val isValid = result.getOrNull()?.valid == true
        val type = if (isValid) EventTypes.OID4VP_RESPONSE_VERIFIED else EventTypes.OID4VP_RESPONSE_FAILED
        val es = eventService ?: return
        es.emitOid4vpSessionHistoryEvent(
            type = type,
            origin = ValidateAuthorizationResponseCommand.COMMAND_ID,
            session = requireNotNull(pendingHistorySession) {
                "OID4VP validation outcome has no persisted authorization session"
            },
            stage = "RESPONSE_VALIDATION",
            outcome = if (isValid) "VERIFIED" else "FAILED",
            errorCode = if (isValid) null else "validation_failed",
        )
    }

    private suspend fun validateOnePresentation(
        queryId: String,
        presentationIndex: Int,
        presentationElement: JsonElement,
        matchingQuery: DcqlCredentialQuery,
        processedArgs: ValidateAuthorizationResponseArgs,
        bindingRequest: AuthorizationRequest,
        holderBindingClientId: String,
        bindingNonce: String,
        effectiveVerifierId: String?,
        effectiveDcqlQueryId: String?,
        effectiveTemplateId: String?,
        statusPolicies: Map<String, CredentialStatusPolicy>,
        persistedJwtIssuerAlgorithms: Set<String>?,
        errors: MutableList<String>,
        accepted: MutableList<AcceptedCredential>,
        rejections: MutableList<CredentialValidationRejection>,
    ) {
        // OID4VP ldp_vc values are JSON objects. The value can be either a credential or
        // a holder-bound presentation, so classify the VCDM document itself before
        // selecting assertionMethod versus authentication proof semantics before
        // trust/status or DCQL result processing; never route an object through a
        // compact-JWT holder-binding path.
        if (presentationElement is JsonObject) {
            if (matchingQuery.format != LDP_VC_FORMAT) {
                errors.add("JSON-object presentation for query '$queryId' requires ldp_vc format")
                return
            }
            val classifiedDocument = VcdmClassifier.classifyDocument(presentationElement)
            if (classifiedDocument.isErr) {
                errors.add(
                    "VCDM document classification failed for query '$queryId' at index $presentationIndex: " +
                        classifiedDocument.error.message.defaultMessage,
                )
                return
            }
            val documentKind = classifiedDocument.value.kind
            if (documentKind == VcdmDocumentKind.CREDENTIAL && matchingQuery.require_cryptographic_holder_binding) {
                errors.add(
                    "Presentation for query '$queryId' at index $presentationIndex rejected: " +
                        "a bare ldp_vc credential cannot satisfy cryptographic holder binding; return a holder-bound VerifiablePresentation",
                )
                return
            }
            val declaredDataIntegrityController = dataIntegrityController(presentationElement, documentKind)
            val diArgs =
                VcdmDataIntegrityVerificationArgs(
                    document = presentationElement,
                    expectedProofPurpose = if (documentKind == VcdmDocumentKind.CREDENTIAL) {
                        ProofPurpose.ASSERTION_METHOD
                    } else {
                        ProofPurpose.AUTHENTICATION
                    },
                    expectedController = declaredDataIntegrityController,
                    expectedDomain = if (documentKind == VcdmDocumentKind.PRESENTATION) holderBindingClientId else null,
                    expectedChallenge = if (documentKind == VcdmDocumentKind.PRESENTATION) bindingNonce else null,
                    requireDomainAndChallenge = documentKind == VcdmDocumentKind.PRESENTATION,
                    verificationMethodResolutionPolicy = processedArgs.verificationMethodResolutionPolicy,
                )
            val diResult = try {
                vcdmDataIntegrityVerifier.verify(diArgs)
            } catch (expected: Exception) {
                errors.add(
                    "Data Integrity verification failed for query '$queryId' at index $presentationIndex: " +
                        (expected.message ?: "unexpected verifier error"),
                )
                return
            }
            if (diResult.isErr) {
                errors.add(
                    "Data Integrity verification failed for query '$queryId' at index $presentationIndex: " +
                        diResult.error.message.defaultMessage,
                )
                return
            }
            // VCDM 2.0 permits omitting `holder`; in that case acceptance must use the
            // controller authenticated by the successful Data Integrity verification and
            // must reject an absent or ambiguous presenter identity. VCDM 1.1 retains
            // its existing holder/controller behavior.
            if (documentKind == VcdmDocumentKind.PRESENTATION &&
                classifiedDocument.value.version == VcdmVersion.V2_0 &&
                declaredDataIntegrityController == null &&
                diResult.value.authenticatedControllers.isEmpty()
            ) {
                errors.add(
                    "Data Integrity VCDM 2.0 presentation without holder requires an authenticated controller",
                )
                return
            }
            val verifiedDocument = diResult.value.verifiedDocument
            val renderedPresentation = JSON_LENIENT.encodeToString(JsonElement.serializer(), presentationElement)
            if (documentKind == VcdmDocumentKind.PRESENTATION) {
                val dataIntegrityRecursionState = VcdmRecursionState(matchingQuery)
                if (matchingQuery.require_cryptographic_holder_binding) {
                    dataIntegrityRecursionState.boundHolder = boundDidHolder(
                        declaredDataIntegrityController ?: diResult.value.authenticatedControllers.singleOrNull(),
                    )
                }
                val childFailure = verifyDataIntegrityPresentationChildren(
                    document = verifiedDocument,
                    queryId = queryId,
                    expectedDomain = holderBindingClientId,
                    expectedChallenge = bindingNonce,
                    expectedAudience = holderBindingClientId,
                    verifierEncryptionJwkThumbprint = processedArgs.verifierEncryptionJwkThumbprint,
                    verifierId = effectiveVerifierId,
                    dcqlQueryId = effectiveDcqlQueryId,
                    templateId = effectiveTemplateId,
                    statusPolicy = statusPolicies[queryId] ?: CredentialStatusPolicy(),
                    trustedAuthentications = processedArgs.trustedAuthentications,
                    verificationMethodResolutionPolicy = processedArgs.verificationMethodResolutionPolicy,
                    issuerAlgAllowlist = persistedJwtIssuerAlgorithms,
                    state = dataIntegrityRecursionState,
                )
                // A nested credential is discarded under its parent's query identity; collect its typed
                // rejections before the failure return discards the presentation.
                rejections.addAll(dataIntegrityRecursionState.rejections)
                if (childFailure != null) {
                    errors.add(
                        "Data Integrity presentation for query '$queryId' at index $presentationIndex rejected at " +
                            "the nested credential verification boundary: $childFailure",
                    )
                    return
                }
                // A holder-authenticated ldp_vc presentation is not an issuer credential. Every nested
                // VC has already had its own proof, trust and status checks applied above, and each one
                // is reported as its own credential.
                if (dataIntegrityRecursionState.credentials.isEmpty()) {
                    errors.add("Data Integrity presentation for query '$queryId' at index $presentationIndex carries no verified credential")
                    return
                }
                dataIntegrityRecursionState.credentials.forEach { child ->
                    accepted.add(
                        acceptedVcdmChild(
                            queryId, child, renderedPresentation, PresentationFormat.LDP_VP,
                            statusPolicies[queryId] ?: CredentialStatusPolicy(),
                        ),
                    )
                }
                return
            }
            val objectIssuer = extractDataIntegrityIssuer(verifiedDocument)
            val objectTrust = validateCredentialTrustForFormat(
                verifierId = effectiveVerifierId,
                dcqlQueryId = effectiveDcqlQueryId,
                templateId = effectiveTemplateId,
                credentialQueryId = queryId,
                presentation = renderedPresentation,
                format = LDP_VC_FORMAT,
                issuer = objectIssuer,
            )
            if (objectTrust.enabled && objectTrust.mode == CredentialTrustValidationMode.DEFAULT_ENFORCE && objectTrust.trusted != true) {
                errors.add(
                    "Credential trust validation failed for query '$queryId' at index $presentationIndex: " +
                        (objectTrust.details ?: objectTrust.status ?: "issuer is not trusted"),
                )
                return
            }
            val statusPolicy = statusPolicies[queryId] ?: CredentialStatusPolicy()
            var statusEvaluation = CredentialStatusEvaluation(CredentialStatusDecision.SKIPPED)
            if (credentialStatusVerifiers.isNotEmpty()) {
                val evaluation = evaluateCredentialStatus(credentialStatusVerifiers, verifiedDocument, statusPolicy)
                statusEvaluation = evaluation
                if (evaluation.decision == CredentialStatusDecision.REJECT) {
                    val rejectedStatus = evaluation.rejectedStatus
                    errors.add(if (rejectedStatus != null) "$queryId is ${describeStatus(rejectedStatus)}" else "$queryId could not be validated")
                    rejections.add(statusRejection(queryId, evaluation))
                    emitStatusRejected(queryId, evaluation)
                    return
                }
            }
            credentialTypeFailure(verifiedDocument, matchingQuery)?.let {
                errors.add("Credential for query '$queryId' at index $presentationIndex rejected: $it")
                return
            }
            val objectType = mostSpecificVcdmType(verifiedDocument)
            val objectProjection = vcdmClaimProjection(verifiedDocument, objectType, includeSubjectId = true)
            accepted.add(
                AcceptedCredential(
                    MatchedCredential(
                        credentialQueryId = queryId,
                        credentialFormat = CredentialFormat.LDP_VC,
                        presentation = renderedPresentation,
                        disclosedClaims = objectProjection.claims.toClaimValues(),
                        issuer = objectIssuer,
                        trust = objectTrust.takeIf { it.enabled || it.trustDomainIds.isNotEmpty() },
                        verificationEvidence = verificationEvidence(renderedPresentation, objectIssuer, objectTrust, statusPolicy, statusEvaluation, verifiedCredentialTemporalFacts(verifiedDocument, vcdm = true)),
                        credentialType = objectType,
                    ),
                    objectProjection.queryRoot,
                ),
            )
            return
        }
        if (presentationElement !is JsonPrimitive || !presentationElement.isString) {
            errors.add(
                "Presentation for query '$queryId' at index $presentationIndex must be a string or JSON object",
            )
            return
        }
        val presentation = presentationElement.content
        // Compact-JWS inputs are classified exactly once here. The classification's
        // document kind is authoritative for routing: a compact credential must not
        // enter JWT VP nonce/audience holder-binding logic.
        val compactClassificationResult =
            if (!presentation.contains('~') && presentation.contains('.')) {
                VcdmClassifier.classifyCompactJws(presentation)
            } else {
                null
            }
        val compactClassification = compactClassificationResult?.getOrNull()
        val detectedCredentialFormat =
            when {
                compactClassification?.document?.kind == VcdmDocumentKind.CREDENTIAL -> compactClassification.credentialFormat
                compactClassification?.document?.kind == VcdmDocumentKind.PRESENTATION -> null
                presentation.contains('.') && !presentation.contains('~') -> null
                presentation.contains('~') ->
                    CredentialFormat.SD_JWT_VC.takeIf {
                        presentation.substringBefore('~').count { character -> character == '.' } == 2
                    }
                presentation.length > MDOC_MIN_ENCODED_LENGTH -> CredentialFormat.MSO_MDOC
                else -> null
            }

        if (detectedCredentialFormat == null && compactClassification?.document?.kind != VcdmDocumentKind.PRESENTATION) {
            val classificationFailure =
                compactClassificationResult?.let { result ->
                    if (result.isErr) result.error.message.defaultMessage else null
                }
            errors.add(
                "Could not determine format of presentation for query '$queryId' at index $presentationIndex" +
                    (classificationFailure?.let { ": $it" } ?: ""),
            )
            return
        }

        // Validate the required Credential Format Identifier.
        //
        // A compact VCDM 2.0 credential is classified directly as
        // `jwt_vc_json-ld`; the JSON-LD shape validator below still
        // enforces the requested schema and context.
        val queryFormat = matchingQuery.format
        val requestedCredentialFormat = CredentialFormat.fromValueLenient(queryFormat)
        val formatMatches = if (compactClassification?.document?.kind == VcdmDocumentKind.PRESENTATION) {
            requestedCredentialFormat != null
        } else if (compactClassification != null) {
            requestedCredentialFormat == compactClassification.credentialFormat
        } else {
            requestedCredentialFormat == detectedCredentialFormat
        }

        if (!formatMatches) {
            errors.add("Credential format '$queryFormat' for query '$queryId' does not match the submitted credential")
            return
        }

        // JWT VP algorithm negotiation is pinned to the authorization request that was
        // persisted for this session. Never accept an algorithm merely because a caller
        // supplied it in a response-side structure: the signed VP must use one of the
        // verifier's original `vp_formats_supported[format].alg_values` values.
        if (
            compactClassification?.document?.kind == VcdmDocumentKind.PRESENTATION &&
            compactClassification.presentationFormat?.isJwt == true
        ) {
            val acceptedMetadataFormat = requestedCredentialFormat?.value ?: queryFormat
            val acceptedAlgorithms = bindingRequest.clientMetadata
                ?.vpFormatsSupported
                ?.get(acceptedMetadataFormat)
                ?.algValuesSupported
            val emittedAlgorithm = (compactClassification.protectedHeader["alg"] as? JsonPrimitive)
                ?.takeIf { it.isString }
                ?.content
            if (acceptedAlgorithms.isNullOrEmpty()) {
                errors.add(
                    "JWT VP for query '$queryId' rejected: persisted authorization request " +
                        "does not advertise non-empty alg_values for $acceptedMetadataFormat",
                )
                return
            }
            if (emittedAlgorithm == null || emittedAlgorithm !in acceptedAlgorithms) {
                errors.add(
                    "JWT VP for query '$queryId' rejected: protected alg '$emittedAlgorithm' " +
                        "is not in the persisted verifier allowlist for $acceptedMetadataFormat: $acceptedAlgorithms",
                )
                return
            }
        }

        // VCDM credentials and presentations are distinct documents. Appendix B requires
        // a secured VP (with nonce/audience binding) when holder binding is requested;
        // a bare VC never enters JWT-VP holder-binding logic. Issuer authenticity and
        // VC semantics are still mandatory when holder binding is disabled.
        val isClassifiedVcdmCredential =
            compactClassification?.document?.kind == VcdmDocumentKind.CREDENTIAL
        var issuer: CredentialIssuerRef? = null
        var trust: CredentialTrustValidation? = null
        if (isClassifiedVcdmCredential) {
            if (matchingQuery.require_cryptographic_holder_binding) {
                errors.add(
                    "Presentation for query '$queryId' at index $presentationIndex rejected: " +
                        "VCDM credential requires a bound Verifiable Presentation when " +
                        "require_cryptographic_holder_binding is true",
                )
                return
            }

            issuer = withFederationEntity(
                extractCredentialIssuer(presentation, requireNotNull(detectedCredentialFormat)),
                presentation,
                processedArgs.trustedAuthentications,
            )
            // Cryptographic issuer verification is the first security callback. Trust
            // validators must not receive attacker-controlled claims until the JWS has
            // verified successfully; this also keeps status lookups behind authenticity.
            val credentialFailure =
                verifyVcdmCredential(
                    presentation,
                    compactClassification,
                    issuer,
                    processedArgs.trustedAuthentications,
                    persistedJwtIssuerAlgorithms,
                )
            if (credentialFailure != null) {
                errors.add(
                    "Presentation for query '$queryId' at index $presentationIndex rejected: " +
                        credentialFailure,
                )
                return
            }
        }

        if (compactClassification?.document?.kind == VcdmDocumentKind.PRESENTATION || compactClassification == null) {
            val bindingArgs =
                VerifyHolderBindingArgs(
                    presentation = presentation,
                    credentialFormat = if (compactClassification?.document?.kind == VcdmDocumentKind.PRESENTATION) null else detectedCredentialFormat,
                    presentationFormat = compactClassification?.presentationFormat,
                    expectedNonce = bindingNonce,
                    expectedAudience = holderBindingClientId,
                    requireCryptographicHolderBinding = matchingQuery.require_cryptographic_holder_binding,
                    trustedAuthentications = processedArgs.trustedAuthentications,
                    clientId = holderBindingClientId,
                    responseUri = bindingRequest.responseUri,
                    responseMode = bindingRequest.responseMode,
                    callerOrigin = holderBindingClientId.takeIf { it.startsWith("origin:") }?.removePrefix("origin:"),
                    expectedMdocDocumentType =
                        (matchingQuery.meta["doctype_value"] as? JsonPrimitive)
                            ?.takeIf { it.isString }
                            ?.content,
                    verifierEncryptionJwkThumbprint = processedArgs.verifierEncryptionJwkThumbprint,
                    mdocDocumentResponseDecryptionKey = processedArgs.mdocDocumentResponseDecryptionKey,
                    mdocDocumentResponseEncryptionParameters = processedArgs.mdocDocumentResponseEncryptionParameters,
                    mdocDocumentResponseEncryptionProviders = processedArgs.mdocDocumentResponseEncryptionProviders,
                    iso18013MdocGeneratedNonce = processedArgs.iso18013MdocGeneratedNonce,
                )
            val bindingResultOrError = verifyHolderBindingCommand.execute(bindingArgs)
            if (bindingResultOrError.isErr) {
                errors.add(
                    "Holder binding verification command failed for query '$queryId' " +
                        "at index $presentationIndex: ${bindingResultOrError.error.message.defaultMessage}",
                )
                return
            }
            val bindingResult = bindingResultOrError.value
            if (!bindingResult.verified) {
                val detail = bindingResult.errors.takeIf { it.isNotEmpty() }?.joinToString("; ") ?: "no detail"
                // Distinguish trust-establishment failure from cryptographic mismatch.
                // For SD-JWT issuer JWTs the verifier sets `issuerTrustEstablished=false`
                // when no key could be resolved through the trust chain (e.g. relative
                // `kid: "#0"` not qualified by `iss`, did:web fetch failed, no trust
                // anchor for an x5c chain). In that state `signatureValid=false` is
                // misleading on its own, so the message calls it out explicitly.
                val rootCause =
                    when {
                        bindingResult.issuerTrustEstablished == false -> {
                            "issuer trust establishment failed (no verification key resolved for the issuer JWT — " +
                                "check kid/iss qualification, did:web reachability, or trust anchors)"
                        }

                        bindingResult.issuerCryptoVerified == false -> {
                            "issuer JWT signature did not verify against the resolved key"
                        }

                        !bindingResult.signatureValid -> {
                            "signature/binding check failed"
                        }

                        !bindingResult.nonceValid -> {
                            "nonce mismatch"
                        }

                        !bindingResult.audienceValid -> {
                            "audience mismatch"
                        }

                        bindingResult.sdHashValid == false -> {
                            "sd_hash mismatch"
                        }

                        else -> {
                            "verification not satisfied"
                        }
                    }
                errors.add(
                    "Holder binding verification failed for query '$queryId' at index " +
                        "$presentationIndex (method=${bindingResult.bindingMethod}, " +
                        "issuerTrustEstablished=${bindingResult.issuerTrustEstablished}, " +
                        "issuerCryptoVerified=${bindingResult.issuerCryptoVerified}, " +
                        "signatureValid=${bindingResult.signatureValid}, " +
                        "nonceValid=${bindingResult.nonceValid}, " +
                        "audienceValid=${bindingResult.audienceValid}): " +
                        "$rootCause — $detail",
                )
                return
            }
        }

        // A VCDM VP may contain multiple VC/EnvelopedVC entries. J4 recursively verifies
        // every child; outer holder proof never substitutes for child issuer proofs. The
        // returned credential-format set is authoritative for DCQL matching and is only
        // available after holder binding and child authentication have succeeded.
        var verifiedPresentationChildren: List<VerifiedVcdmCredential> = emptyList()
        if (compactClassification?.document?.kind == VcdmDocumentKind.PRESENTATION) {
            val recursiveResult =
                verifyVcdmPresentationChildren(
                    artifact = presentation,
                    classification = compactClassification,
                    queryId = queryId,
                    expectedNonce = bindingNonce,
                    expectedAudience = holderBindingClientId,
                    verifierEncryptionJwkThumbprint = processedArgs.verifierEncryptionJwkThumbprint,
                    verifierId = effectiveVerifierId,
                    dcqlQueryId = effectiveDcqlQueryId,
                    templateId = effectiveTemplateId,
                    statusPolicy = statusPolicies[queryId] ?: CredentialStatusPolicy(),
                    trustedAuthentications = processedArgs.trustedAuthentications,
                    verificationMethodResolutionPolicy = processedArgs.verificationMethodResolutionPolicy,
                    issuerAlgAllowlist = persistedJwtIssuerAlgorithms,
                    boundHolder = if (matchingQuery.require_cryptographic_holder_binding) {
                        boundDidHolder(compactPresentationHolder(compactClassification))
                    } else {
                        null
                    },
                    matchingQuery = matchingQuery,
                )
            rejections.addAll(recursiveResult.rejections)
            if (recursiveResult.error != null) {
                errors.add(
                    "VCDM presentation for query '$queryId' at index $presentationIndex rejected at " +
                        "the J4 recursive verification boundary: ${recursiveResult.error}",
                )
                return
            }
            val matchedCredentialFormat = requestedCredentialFormat
                ?: run {
                    errors.add("Credential format '$queryFormat' is not supported for query '$queryId'")
                    return
                }
            if (matchedCredentialFormat !in recursiveResult.credentialFormats) {
                errors.add("Credential format '$queryFormat' for query '$queryId' does not match any verified presentation child")
                return
            }
            verifiedPresentationChildren = recursiveResult.credentials
        }

        // VCDM 2.0 + JSON-LD: enforce the same `@context` and JSON
        // Schema validators that the issuer side runs. Only runs
        // when the verifier asked for `jwt_vc_json-ld`; SD-JWT,
        // mdoc, and VCDM 1.1 jwt_vc_json presentations skip the
        // JWT-body decode entirely.
        if (queryFormat == CredentialFormat.JWT_VC_JSON_LD.value) {
            val vcLdViolation = validateVcLdJsonShape(presentation)
            if (vcLdViolation != null) {
                errors.add(
                    "VCDM 2.0 + JSON-LD validation failed for query '$queryId' at index $presentationIndex: " +
                        vcLdViolation,
                )
                return
            }
        }

        // The outer VCDM VP is a holder-authenticated presentation, not a credential
        // issued by its `iss`/holder. Its child VCs have already gone through issuer
        // trust, authenticity, semantics, and status checks above. Do not re-run those
        // credential checks against the VP holder or expose that holder as the issuer of
        // an inner credential.
        if (compactClassification?.document?.kind == VcdmDocumentKind.PRESENTATION) {
            if (requestedCredentialFormat == null) {
                errors.add("Credential format '$queryFormat' is not supported for query '$queryId'")
                return
            }
            // The VP's own envelope carries no credential claims; every verified child credential is
            // reported as its own entry.
            if (verifiedPresentationChildren.isEmpty()) {
                errors.add("VCDM presentation for query '$queryId' at index $presentationIndex carries no verified credential")
                return
            }
            verifiedPresentationChildren.forEach { child ->
                accepted.add(
                    acceptedVcdmChild(
                        queryId, child, presentation, compactClassification.presentationFormat,
                        statusPolicies[queryId] ?: CredentialStatusPolicy(),
                    ),
                )
            }
            return
        }

        val resolvedIssuer = issuer ?: withFederationEntity(
            extractCredentialIssuer(presentation, requireNotNull(detectedCredentialFormat)),
            presentation,
            processedArgs.trustedAuthentications,
        )
        val resolvedTrust =
            trust
                ?: if (detectedCredentialFormat == CredentialFormat.MSO_MDOC) {
                    validateMdocTrustForAllDocuments(
                        verifierId = effectiveVerifierId,
                        dcqlQueryId = effectiveDcqlQueryId,
                        templateId = effectiveTemplateId,
                        credentialQueryId = queryId,
                        presentation = presentation,
                        firstIssuer = resolvedIssuer,
                    )
                } else {
                    validateCredentialTrust(
                        verifierId = effectiveVerifierId,
                        dcqlQueryId = effectiveDcqlQueryId,
                        templateId = effectiveTemplateId,
                        credentialQueryId = queryId,
                        presentation = presentation,
                        detectedFormat = requireNotNull(detectedCredentialFormat),
                        issuer = resolvedIssuer,
                    )
                }
        if (resolvedTrust.enabled && resolvedTrust.mode == CredentialTrustValidationMode.DEFAULT_ENFORCE && resolvedTrust.trusted != true) {
            errors.add(
                "Credential trust validation failed for query '$queryId' at index $presentationIndex: " +
                    (resolvedTrust.details ?: resolvedTrust.status ?: "issuer is not trusted by the resolved trust domains"),
            )
            log.warn("Credential '$queryId' rejected by trust-domain validation: ${resolvedTrust.details ?: resolvedTrust.status}")
            return
        }

        // Credential status (revocation/suspension) check. Runs only when status verifiers are
        // wired; otherwise skipped entirely. The reported claims leave out the `status` claim,
        // so we read the full credential payload separately. A REJECT discards the presentation
        // per OID4VP §10, the same as a holder-binding failure.
        val statusInput = credentialStatusInputFor(
            presentation,
            requireNotNull(detectedCredentialFormat),
            processedArgs.trustedAuthentications,
        )
        val statusPolicy = statusPolicies[queryId] ?: CredentialStatusPolicy()
        var statusEvaluation = CredentialStatusEvaluation(CredentialStatusDecision.SKIPPED)
        if (credentialStatusVerifiers.isEmpty()) {
            if (requireNotNull(detectedCredentialFormat) == CredentialFormat.MSO_MDOC &&
                statusInput.hasMdocStatusReference()
            ) {
                errors.add("$queryId could not be validated: mso_mdoc status verifier is not configured")
                log.warn("Credential '$queryId' carries an mso_mdoc status reference but no status verifier is configured")
                return
            }
        } else {
            val evaluation = evaluateCredentialStatus(credentialStatusVerifiers, statusInput ?: CredentialStatusInput(), statusPolicy)
            statusEvaluation = evaluation
            if (evaluation.decision == CredentialStatusDecision.REJECT) {
                // User-facing: just the credential and its state ("EuPid is revoked"). The status
                // list URI / index are operator diagnostics — logged and emitted as an event, not
                // returned to the end user.
                val word = evaluation.rejectedStatus?.let { describeStatus(it) }
                errors.add(if (word != null) "$queryId is $word" else "$queryId could not be validated")
                log.warn("Credential '$queryId' rejected by status check: ${evaluation.reason}")
                rejections.add(statusRejection(queryId, evaluation))
                emitStatusRejected(queryId, evaluation)
                return
            }
        }

        // Extract the claims of every credential in the presentation: one for a compact credential or an
        // SD-JWT, one per document for an mdoc DeviceResponse.
        val compactVcdmCredential = compactClassification?.takeIf { it.document.kind == VcdmDocumentKind.CREDENTIAL }?.document?.json
        val typeCheckedCredential =
            compactVcdmCredential
                ?: if (detectedCredentialFormat == CredentialFormat.SD_JWT_VC) {
                    // vct and vct#integrity are never selectively disclosable, so the issuer-signed JWT alone carries them.
                    SdJwtCodec.parse(presentation.substringBefore('~') + "~").getOrElse {
                        errors.add("SD-JWT VC for query '$queryId' at index $presentationIndex could not be parsed for its type check: ${it.message.defaultMessage}")
                        return
                    }.payload.fullPayload
                } else {
                    null
                }
        if (typeCheckedCredential != null) {
            credentialTypeFailure(typeCheckedCredential, matchingQuery)?.let {
                errors.add("Credential for query '$queryId' at index $presentationIndex rejected: $it")
                return
            }
        }
        val projections =
            if (compactVcdmCredential != null) {
                listOf(vcdmClaimProjection(compactVcdmCredential, mostSpecificVcdmType(compactVcdmCredential)))
            } else {
                extractClaimProjections(presentation, requireNotNull(detectedCredentialFormat)).getOrElse { failure ->
                    errors.add(
                        "Claims of the presentation for query '$queryId' at index $presentationIndex could not be read: " +
                            failure.message.defaultMessage,
                    )
                    return
                }
            }
        val documentIssuers = if (detectedCredentialFormat == CredentialFormat.MSO_MDOC) extractMdocIssuers(presentation) else emptyList()
        val temporalFacts =
            verifiedCredentialTemporalFacts(
                statusInput?.claims?.takeIf { detectedCredentialFormat != CredentialFormat.MSO_MDOC },
                vcdm = detectedCredentialFormat == CredentialFormat.JWT_VC_JSON || detectedCredentialFormat == CredentialFormat.JWT_VC_JSON_LD,
            )
        projections.forEachIndexed { index, projection ->
            val entryIssuer = if (documentIssuers.size == projections.size) documentIssuers[index] else resolvedIssuer
            accepted.add(
                AcceptedCredential(
                    MatchedCredential(
                        credentialQueryId = queryId,
                        credentialFormat = requireNotNull(detectedCredentialFormat),
                        presentationFormat = null,
                        presentation = presentation,
                        disclosedClaims = projection.claims.toClaimValues(),
                        issuer = entryIssuer,
                        trust = resolvedTrust.takeIf { it.enabled || it.trustDomainIds.isNotEmpty() },
                        verificationEvidence = verificationEvidence(presentation, entryIssuer, resolvedTrust, statusPolicy, statusEvaluation, temporalFacts),
                        credentialType = projection.credentialType,
                    ),
                    projection.queryRoot,
                ),
            )
        }
    }

    /** A verified child credential of a W3C presentation, reported as its own entry. */
    private fun acceptedVcdmChild(
        queryId: String,
        child: VerifiedVcdmCredential,
        presentation: String,
        presentationFormat: PresentationFormat?,
        statusPolicy: CredentialStatusPolicy,
    ): AcceptedCredential {
        val type = mostSpecificVcdmType(child.document)
        val projection = vcdmClaimProjection(child.document, type)
        return AcceptedCredential(
            MatchedCredential(
                credentialQueryId = queryId,
                credentialFormat = child.format,
                presentationFormat = presentationFormat,
                presentation = presentation,
                disclosedClaims = projection.claims.toClaimValues(),
                issuer = child.issuer,
                trust = child.trust.takeIf { it.enabled || it.trustDomainIds.isNotEmpty() },
                verificationEvidence = verificationEvidence(presentation, child.issuer, child.trust, statusPolicy, child.statusEvaluation, child.temporalFacts),
                credentialType = type,
            ),
            projection.queryRoot,
        )
    }

    /**
     * Applies the credential type constraint of [query] to an authenticated credential. Returns the
     * reason the credential is refused, or null when it satisfies the query. Formats without a type
     * constraint handled by [CredentialTypeMatcher] are left to their existing checks.
     */
    private suspend fun credentialTypeFailure(
        credential: JsonObject,
        query: DcqlCredentialQuery,
    ): String? {
        if (query.format !in TYPE_CHECKED_FORMATS) return null
        val matches =
            credentialTypeMatcher.matches(credential, query)
                .getOrElse { return "credential type could not be verified: ${it.message.defaultMessage}" }
        return if (matches) null else "credential type does not match query '${query.id}'"
    }

    /** The most specific W3C VCDM type: the last `type` entry other than `VerifiableCredential`. */
    private fun mostSpecificVcdmType(credential: JsonObject): String? =
        when (val type = credential["type"]) {
            is JsonPrimitive -> type.takeIf { it.isString }?.content
            is JsonArray -> type.mapNotNull { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content }
                .lastOrNull { it != "VerifiableCredential" }
                ?: type.mapNotNull { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content }.lastOrNull()
            else -> null
        }

    private fun verificationEvidence(
        presentation: String,
        issuer: CredentialIssuerRef?,
        trust: CredentialTrustValidation,
        policy: CredentialStatusPolicy,
        evaluation: CredentialStatusEvaluation,
        temporalFacts: VerifiedCredentialTemporalFacts?,
    ) = VerifiedCredentialEvidence(
        presentationSha256 = hash(presentation.encodeToByteArray(), DigestAlg.SHA256).encodeToBase64Url(),
        verifiedAtEpochMillis = Clock.System.now().toEpochMilliseconds(),
        issuer = issuer,
        trust = trust,
        temporalFacts = temporalFacts,
        status = VerifiedCredentialStatus(
            evaluation = VerifiedCredentialStatusOutcome.valueOf(evaluation.decision.name),
            resolvedValues = evaluation.resolved.map { it.value },
            required = policy.requireStatus,
            rejectOnUnresolvable = policy.rejectOnUnresolvable,
        ),
    )

    private suspend fun doExecuteInternal(
        args: ValidateAuthorizationResponseArgs,
        applyDuring: (ValidateAuthorizationResponseArgs) -> ValidateAuthorizationResponseArgs,
    ): IdkResult<ValidationResult, IdkError> {
        val processedArgs = applyDuring(args)

        log.debug("Validating authorization response against DCQL query")

        val parsedResponse = processedArgs.parsedResponse
        val originalRequest = processedArgs.originalRequest
        val callerExpectedNonce = processedArgs.expectedNonce

        val errors = mutableListOf<String>()
        val accepted = mutableListOf<AcceptedCredential>()
        val rejections = mutableListOf<CredentialValidationRejection>()
        // Query IDs the wallet actually submitted a presentation for. A required credential that WAS
        // submitted but then discarded (status rejection, holder-binding failure, ...) must not also be
        // reported as "not found" — the specific discard reason is already in `errors`.
        val submittedQueryIds = mutableSetOf<String>()

        // `doExecute` has already loaded and retained the session before entering this method.
        // Use that exact persisted object as the authority for algorithm negotiation; a
        // response-side request/caller structure must never be able to replace it.
        val authorizationSession =
            requireNotNull(pendingHistorySession) {
                "OID4VP validation has no persisted authorization session"
            }
        // The persisted authorization session is the verifier-owned DCQL authority. A response
        // caller must not replace the requested mdoc document type (or any other query contract)
        // by supplying a different query alongside the response.
        val dcqlQuery = authorizationSession.dcqlQuery
        // Trust-domain attachments for OID4VP_VERIFIER are keyed by the tenant runtime instance
        // id. Keep the persisted verifier party UUID for authentication/session identity, but do
        // not send it as the trust consumer id.
        val effectiveVerifierId = authorizationSession.instanceId
        val effectiveDcqlQueryId = processedArgs.dcqlQueryId ?: authorizationSession.dcqlQueryId
        val effectiveTemplateId = processedArgs.templateId ?: authorizationSession.templateId
        val persistedRequest = authorizationSession.authorizationRequest
        val bindingRequest = persistedRequest
        val bindingNonce = persistedRequest.nonce ?: callerExpectedNonce
        val holderBindingClientId = holderBindingClientId(bindingRequest)
        if (holderBindingClientId == null) {
            errors.add("Digital Credentials request has no single valid expected browser origin")
            return Ok(ValidationResult(valid = false, errors = errors))
        }
        if (persistedRequest.clientId != originalRequest.clientId) {
            errors.add("Authorization request client_id does not match the persisted session")
        }
        if (persistedRequest.nonce != null && persistedRequest.nonce != callerExpectedNonce) {
            errors.add("Authorization request nonce does not match the persisted session")
        }

        // Per-DCQL-query credential status policies, pinned on the session at create time. Loaded only
        // to drive status acceptance; absence (no session / no map) falls back to the strict default
        // per query. An authenticated mso_mdoc status reference is never silently accepted merely
        // because a deployment forgot to contribute the mdoc status verifier.
        val statusPolicies: Map<String, CredentialStatusPolicy> =
            if (credentialStatusVerifiers.isEmpty()) {
                emptyMap()
            } else {
                authorizationSession.credentialStatusPolicies ?: emptyMap()
            }

        // Validate state parameter
        if (originalRequest.state != null && parsedResponse.state != originalRequest.state) {
            errors.add("State mismatch: expected '${originalRequest.state}', got '${parsedResponse.state}'")
        }

        // Validate each presentation in the VP token (DCQL format: Map of queryId -> presentations).
        //
        // OID4VP §8.1: each Presentation value is Credential-Format dependent — a JSON string
        // for compact formats (dc+sd-jwt, jwt_vc_json, mso_mdoc) or a JSON object for the W3C
        // Data Integrity format (ldp_vc). We branch on the element shape and NEVER
        // blanket-cast to jsonPrimitive.
        val vpToken = parsedResponse.vpToken

        // Issuers that verifier policy admits but cannot enumerate in advance (for example members of
        // an admitted OpenID Federation) get their admitted material before any credential is verified.
        val effectiveArgs =
            processedArgs.credentialIssuerAuthenticationLookup?.let { lookup ->
                val resolved =
                    PresentedCredentialIssuers.resolve(
                        vpToken.presentationElements.values.flatten(),
                        processedArgs.trustedAuthentications,
                        lookup,
                    )
                if (resolved.isEmpty()) processedArgs else processedArgs.copy(trustedAuthentications = processedArgs.trustedAuthentications + resolved)
            } ?: processedArgs

        for ((queryId, presentationElements) in vpToken.presentationElements) {
            submittedQueryIds.add(queryId)
            // Validate the credential query ID exists in the DCQL query
            val credentialQueries = dcqlQuery.credentials
            val matchingQuery = credentialQueries.find { it.id == queryId }

            if (matchingQuery == null) {
                errors.add("Credential query ID '$queryId' from vp_token not found in DCQL query")
                continue
            }
            // A query that does not allow `multiple` accepts one presentation, counted before any child
            // credential of a presentation is expanded. VpToken already refuses an empty presentation list.
            if (presentationElements.size > 1 && !matchingQuery.multiple) {
                errors.add("Credential query '$queryId' allows one presentation but ${presentationElements.size} were submitted")
                continue
            }
            // The persisted verifier metadata is the sole issuer-JWS algorithm authority. Thread
            // this per-query value through every VCDM child recursion boundary, including VCDM 2
            // nested presentations and envelopes.
            val persistedJwtIssuerAlgorithms = bindingRequest.clientMetadata
                ?.vpFormatsSupported
                ?.get(matchingQuery.format)
                ?.algValuesSupported
                ?.toSet()

            // Validate each presentation for this query ID
            for ((presentationIndex, presentationElement) in presentationElements.withIndex()) {
                val errorsBefore = errors.size
                val presented = mutableListOf<AcceptedCredential>()
                validateOnePresentation(
                    queryId = queryId,
                    presentationIndex = presentationIndex,
                    presentationElement = presentationElement,
                    matchingQuery = matchingQuery,
                    processedArgs = effectiveArgs,
                    bindingRequest = bindingRequest,
                    holderBindingClientId = holderBindingClientId,
                    bindingNonce = bindingNonce ?: processedArgs.expectedNonce,
                    effectiveVerifierId = effectiveVerifierId,
                    effectiveDcqlQueryId = effectiveDcqlQueryId,
                    effectiveTemplateId = effectiveTemplateId,
                    statusPolicies = statusPolicies,
                    persistedJwtIssuerAlgorithms = persistedJwtIssuerAlgorithms,
                    errors = errors,
                    accepted = presented,
                    rejections = rejections,
                )
                if (errors.size > errorsBefore) continue
                // Every credential of the presentation must hold the claims the query asks for on its own,
                // so one complete credential never hides an incomplete sibling, and none is kept otherwise.
                if (presented.any { !satisfiesRequestedClaims(matchingQuery, it.queryRoot) }) {
                    errors.add("Credential for query '$queryId' at index $presentationIndex does not contain the requested claims")
                    continue
                }
                accepted.addAll(presented)
            }
        }

        val matchedCredentials = accepted.map { it.matched }

        // Validate all required credentials are present
        val requiredCredentials =
            dcqlQuery.credentials.filter { query ->
                // If no credential_sets, all credentials are required
                dcqlQuery.credential_sets.isNullOrEmpty()
            }

        for (required in requiredCredentials) {
            if (matchedCredentials.none { it.credentialQueryId == required.id }) {
                // Only "not found" when the wallet never submitted it. If it was submitted but
                // discarded (e.g. revoked status), the specific rejection error already explains why,
                // so adding "not found" on top would just confuse the end user.
                if (required.id !in submittedQueryIds) {
                    errors.add("Required credential '${required.id}' not found in response")
                }
            }
        }

        // Validate credential_sets if present (OR logic)
        dcqlQuery.credential_sets?.filter { it.required }?.forEach { credentialSet ->
            val anySatisfied =
                credentialSet.options.any { option ->
                    option.all { credId ->
                        matchedCredentials.any { it.credentialQueryId == credId }
                    }
                }
            if (!anySatisfied) {
                errors.add("No option in required credential_set satisfied")
            }
        }

        val valid = errors.isEmpty()

        log.info("Validation result: valid=$valid, matched=${matchedCredentials.size}, errors=${errors.size}")

        val result =
            ValidationResult(
                valid = valid,
                matchedCredentials = matchedCredentials,
                errors = errors,
                rejections = rejections,
            )

        return Ok(result)
    }

    /**
     * If [presentation] is a JWT compact serialization whose payload looks
     * like a VCDM 2.0 + JSON-LD credential (i.e. has a top-level `@context`
     * containing `https://www.w3.org/ns/credentials/v2`), validate the
     * `@context` chain (UNTP `@vocab` MUST-NOT) and the JSON Schema
     * registered for the primary `type`. Returns null on success or when the
     * presentation does not look like VCDM 2.0; returns a human-readable
     * reason string on validation failure.
     *
     * Holder binding has already been verified by the time this is called,
     * so we can safely decode the payload without re-checking the signature.
     * Decode is best-effort: malformed bytes return null (no crash).
     */
    private suspend fun validateVcLdJsonShape(presentation: String): String? {
        val payload = decodeJwtPayloadOrNull(presentation) ?: return null
        val context = payload["@context"] ?: return null
        if (!referencesVcdm2Context(context)) return null

        val contextResult =
            jsonLdContextValidator.validate(
                ValidateJsonLdContextInput(context = context),
            )
        if (contextResult.isErr) {
            return formatJsonLdError(contextResult.error)
        }

        // Schema validation runs against the VC body. Our format handler
        // emits the VC body merged with JWT registered claims at the JWT
        // root, so the same payload validates cleanly: JSON Schema's
        // `additionalProperties: true` (default for UNTP schemas) lets the
        // extra `iss`/`iat`/`exp`/`sub`/`cnf` keys pass through.
        val primaryType = primaryCredentialTypeOrNull(payload) ?: return null
        val schemaResult =
            jsonLdSchemaValidator.validate(
                ValidateJsonLdSchemaInput(payload = payload, credentialType = primaryType),
            )
        // Unknown types (no schema in the registry) are a soft pass; schema
        // mismatches and malformed schemas abort.
        if (schemaResult.isErr && schemaResult.error !is JsonLdError.NoSchemaRegistered) {
            return formatJsonLdError(schemaResult.error)
        }

        return null
    }

    /**
     * Verify and evaluate every secured child in an ldp_vc VerifiablePresentation. The Data
     * Integrity adapter verifies one document at a time; this format-aware boundary dispatches
     * direct DI children and JOSE envelopes, then applies issuer trust and status independently.
     * A VP holder is deliberately never used as a child VC issuer.
     */
    private suspend fun verifyDataIntegrityPresentationChildren(
        document: JsonObject,
        queryId: String,
        expectedDomain: String?,
        expectedChallenge: String?,
        expectedAudience: String,
        verifierEncryptionJwkThumbprint: ByteArray?,
        verifierId: String?,
        dcqlQueryId: String?,
        templateId: String?,
        statusPolicy: CredentialStatusPolicy,
        trustedAuthentications: List<TrustedAuthenticationResolution>,
        verificationMethodResolutionPolicy: VerificationMethodResolutionPolicy,
        issuerAlgAllowlist: Set<String>?,
        depth: Int = 0,
        state: VcdmRecursionState,
    ): String? {
        if (depth > VCDM_MAX_RECURSION_DEPTH) return "maximum nested Data Integrity presentation depth exceeded"
        if (depth == 0 && state.decodedBytes == 0L) {
            state.decodedBytes = document.toString().encodeToByteArray().size.toLong()
            if (state.decodedBytes > VCDM_MAX_DECODED_BYTES) return "maximum VCDM decoded byte size exceeded"
        }
        val parentClassification = VcdmClassifier.classifyDocument(document)
            .getOrElse { return "VCDM Data Integrity presentation classification failed: ${it.message.defaultMessage}" }
        if (parentClassification.kind != VcdmDocumentKind.PRESENTATION) {
            return "VCDM Data Integrity child container is not a VerifiablePresentation"
        }
        val childrenElement = dataIntegrityChildren(document)
            ?: return "VCDM Data Integrity presentation has no verifiableCredential entries"
        val children = when (childrenElement) {
            is JsonObject -> listOf(childrenElement)
            is JsonArray -> childrenElement
            is JsonPrimitive -> {
                if (parentClassification.version == VcdmVersion.V1_1 && childrenElement.isString) {
                    listOf(childrenElement)
                } else {
                    return "VCDM Data Integrity verifiableCredential has an invalid scalar child"
                }
            }
            else -> return "VCDM Data Integrity verifiableCredential must contain secured children"
        }
        if (children.isEmpty()) return "VCDM Data Integrity presentation has an empty verifiableCredential collection"

        for ((index, child) in children.withIndex()) {
            if (parentClassification.version == VcdmVersion.V1_1) {
                val compactFailure =
                    verifyVcdm11Child(
                        child = child,
                        queryId = queryId,
                        verifierId = verifierId,
                        dcqlQueryId = dcqlQueryId,
                        templateId = templateId,
                        statusPolicy = statusPolicy,
                        trustedAuthentications = trustedAuthentications,
                        verificationMethodResolutionPolicy = verificationMethodResolutionPolicy,
                        issuerAlgAllowlist = issuerAlgAllowlist,
                        state = state,
                    )
                if (compactFailure != null) return "verifiableCredential child[$index] rejected: $compactFailure"
                continue
            }
            val childObject = child as? JsonObject
                ?: return "verifiableCredential child[$index] is not a JSON object"
            val childTypes = strictStringOrStringArray(childObject["type"])
            if (parentClassification.version == VcdmVersion.V2_0 && childTypes?.any { it in VCDM2_ENVELOPED_TYPES } == true) {
                val envelopeFailure =
                    verifyVcdm2EnvelopedChild(
                        child = childObject,
                        queryId = queryId,
                        expectedNonce = expectedChallenge,
                        expectedAudience = expectedAudience,
                        verifierEncryptionJwkThumbprint = verifierEncryptionJwkThumbprint,
                        verifierId = verifierId,
                        dcqlQueryId = dcqlQueryId,
                        templateId = templateId,
                        statusPolicy = statusPolicy,
                        trustedAuthentications = trustedAuthentications,
                        verificationMethodResolutionPolicy = verificationMethodResolutionPolicy,
                        issuerAlgAllowlist = issuerAlgAllowlist,
                        depth = depth,
                        state = state,
                    )
                if (envelopeFailure != null) return "verifiableCredential child[$index] rejected: $envelopeFailure"
                continue
            }
            if (state.nodes >= VCDM_MAX_RECURSION_NODES) return "maximum nested Data Integrity presentation node count exceeded"
            val childArtifact = childObject.toString()
            if (!state.artifacts.add(childArtifact)) return "verifiableCredential child[$index] is duplicate or cyclic"
            state.decodedBytes += childArtifact.encodeToByteArray().size
            if (state.decodedBytes > VCDM_MAX_DECODED_BYTES) return "maximum VCDM decoded byte size exceeded"
            state.nodes++
            val childClassification = VcdmClassifier.classifyDocument(childObject)
                .getOrElse { return "verifiableCredential child[$index] VCDM classification failed: ${it.message.defaultMessage}" }
            val childKind = childClassification.kind
            if (
                childKind == VcdmDocumentKind.PRESENTATION &&
                (parentClassification.version != VcdmVersion.V2_0 || childClassification.version != VcdmVersion.V2_0)
            ) {
                return "verifiableCredential child[$index] nested presentations require VCDM 2.0 at both levels"
            }
            val childController = dataIntegrityController(childObject, childKind)
            val childResult = try {
                vcdmDataIntegrityVerifier.verify(
                    VcdmDataIntegrityVerificationArgs(
                        document = childObject,
                        expectedProofPurpose = if (childKind == VcdmDocumentKind.CREDENTIAL) {
                            ProofPurpose.ASSERTION_METHOD
                        } else {
                            ProofPurpose.AUTHENTICATION
                        },
                        expectedController = childController,
                        expectedDomain = if (childKind == VcdmDocumentKind.PRESENTATION) expectedDomain else null,
                        expectedChallenge = if (childKind == VcdmDocumentKind.PRESENTATION) expectedChallenge else null,
                        requireDomainAndChallenge = childKind == VcdmDocumentKind.PRESENTATION,
                        verificationMethodResolutionPolicy = verificationMethodResolutionPolicy,
                    ),
                )
            } catch (expected: Exception) {
                return "verifiableCredential child[$index] Data Integrity verification failed: ${expected.message ?: "unexpected verifier error"}"
            }
            if (childResult.isErr) return "verifiableCredential child[$index] Data Integrity verification failed: ${childResult.error.message.defaultMessage}"
            if (childKind == VcdmDocumentKind.PRESENTATION &&
                childClassification.version == VcdmVersion.V2_0 &&
                childController == null &&
                childResult.value.authenticatedControllers.isEmpty()
            ) {
                return "verifiableCredential child[$index] holderless VCDM 2.0 presentation requires an authenticated controller"
            }
            val verifiedChild = childResult.value.verifiedDocument
            if (childKind == VcdmDocumentKind.PRESENTATION) {
                val nestedHolder = childController ?: childResult.value.authenticatedControllers.singleOrNull()
                val nestedFailure = state.withPresentationHolder(nestedHolder) { verifyDataIntegrityPresentationChildren(
                    document = verifiedChild,
                    queryId = queryId,
                    expectedDomain = expectedDomain,
                    expectedChallenge = expectedChallenge,
                    expectedAudience = expectedAudience,
                    verifierEncryptionJwkThumbprint = verifierEncryptionJwkThumbprint,
                    verifierId = verifierId,
                    dcqlQueryId = dcqlQueryId,
                    templateId = templateId,
                    statusPolicy = statusPolicy,
                    trustedAuthentications = trustedAuthentications,
                    verificationMethodResolutionPolicy = verificationMethodResolutionPolicy,
                    issuerAlgAllowlist = issuerAlgAllowlist,
                    depth = depth + 1,
                    state = state,
                ) }
                if (nestedFailure != null) return "verifiableCredential child[$index] rejected: $nestedFailure"
            } else {
                holderSubjectBindingFailure(verifiedChild, state)?.let { return "verifiableCredential child[$index] $it" }
                val issuer = extractDataIntegrityIssuer(childObject) ?: extractDataIntegrityIssuer(verifiedChild)
                val trust = validateCredentialTrustForFormat(
                    verifierId = verifierId,
                    dcqlQueryId = dcqlQueryId,
                    templateId = templateId,
                    credentialQueryId = queryId,
                    presentation = JSON_LENIENT.encodeToString(JsonElement.serializer(), childObject),
                    format = LDP_VC_FORMAT,
                    issuer = issuer,
                )
                if (trust.enabled && trust.mode == CredentialTrustValidationMode.DEFAULT_ENFORCE && trust.trusted != true) {
                    return "verifiableCredential child[$index] trust validation failed: ${trust.details ?: trust.status ?: "issuer is not trusted"}"
                }
                val statusEvaluation =
                    evaluateChildStatus(queryId, state) { evaluateCredentialStatus(credentialStatusVerifiers, verifiedChild, statusPolicy) }
                        ?: return "verifiableCredential child[$index] status rejected"
                state.credentials += dataIntegrityCredential(verifiedChild, issuer, trust, statusEvaluation)
                credentialTypeFailure(verifiedChild, state.credentialQuery)?.let { return "verifiableCredential child[$index] $it" }
            }
        }
        return null
    }

    /**
     * Evaluates the status of one child credential of a W3C presentation. The result is `SKIPPED` when no status
     * verifier is wired, and `null` after recording the rejection when the credential is rejected.
     */
    private suspend fun evaluateChildStatus(
        queryId: String,
        state: VcdmRecursionState,
        evaluate: suspend () -> CredentialStatusEvaluation,
    ): CredentialStatusEvaluation? {
        if (credentialStatusVerifiers.isEmpty()) return CredentialStatusEvaluation(CredentialStatusDecision.SKIPPED)
        val evaluation = evaluate()
        if (evaluation.decision == CredentialStatusDecision.REJECT) {
            state.rejections.add(statusRejection(queryId, evaluation))
            emitStatusRejected(queryId, evaluation)
            return null
        }
        return evaluation
    }

    private fun dataIntegrityCredential(
        verifiedDocument: JsonObject,
        issuer: CredentialIssuerRef?,
        trust: CredentialTrustValidation,
        statusEvaluation: CredentialStatusEvaluation,
    ) = VerifiedVcdmCredential(
        document = verifiedDocument,
        format = CredentialFormat.LDP_VC,
        issuer = issuer,
        trust = trust,
        statusEvaluation = statusEvaluation,
        temporalFacts = verifiedCredentialTemporalFacts(verifiedDocument, vcdm = true),
    )

    private fun dataIntegrityChildren(document: JsonObject): JsonElement? {
        return document["verifiableCredential"]
    }

    private fun dataIntegrityController(document: JsonObject, kind: VcdmDocumentKind): String? {
        val field = if (kind == VcdmDocumentKind.CREDENTIAL) "issuer" else "holder"
        return identifier(document[field])
    }

    private fun identifier(element: JsonElement?): String? = when (element) {
        is JsonPrimitive -> element.takeIf { it.isString }?.content
        is JsonObject -> (element["id"] as? JsonPrimitive)?.takeIf { it.isString }?.content
        else -> null
    }

    /**
     * OID4VP 1.0 Cryptographic Holder Binding: the presented credential references the key whose
     * control the holder proves in the presentation. For a DID holder:
     *  - every VCDM credential may name the holder as a `credentialSubject.id` (VCDM 1.1 section
     *    6.3.1: `sub` MUST represent that id; VCDM 2.0 section 4.8);
     *  - a VCDM 2.0 credential secured with JOSE may instead confirm a holder key with `cnf`
     *    (VC-JOSE-COSE section 4.1.3, RFC 7800), here a `kid` that is a DID URL of the holder
     *    (VC-JOSE-COSE section 4.2). VCDM 1.1 JWTs define no `cnf`, so the caller passes no
     *    confirmation for them.
     * A non-DID holder authenticates only through an exactly admitted source in holder binding
     * and is not matched here.
     */
    private fun boundDidHolder(holder: String?): String? = holder?.takeIf { it.startsWith("did:") }

    /** The VCDM presentation holder; for a compact JWT VP the signed `iss` when `holder` is absent. */
    private fun compactPresentationHolder(classification: VcdmClassification): String? =
        identifier(classification.document.json["holder"] ?: classification.rawPayload["iss"])

    private fun holderSubjectBindingFailure(
        credential: JsonObject,
        state: VcdmRecursionState,
        vcJoseConfirmation: List<JsonObject?> = emptyList(),
    ): String? {
        val holder = state.boundHolder ?: return null
        val confirmedKids = vcJoseConfirmation.mapNotNull { (it?.get("cnf") as? JsonObject)?.let { cnf -> identifier(cnf["kid"]) } }
        if (confirmedKids.any { it.substringBefore('#') == holder }) return null
        val subjects = when (val subject = credential["credentialSubject"]) {
            is JsonObject -> listOf(subject)
            is JsonArray -> subject.filterIsInstance<JsonObject>()
            else -> emptyList()
        }
        if (subjects.any { identifier(it["id"]) == holder }) return null
        return "credential is not bound to the presentation holder: no credentialSubject.id or VC-JOSE-COSE cnf.kid names it"
    }

    /** Verifies a nested presentation's children against that presentation's own holder. */
    private inline fun <T> VcdmRecursionState.withPresentationHolder(holder: String?, block: () -> T): T {
        val outer = boundHolder
        boundHolder = outer?.let { boundDidHolder(holder) }
        try {
            return block()
        } finally {
            boundHolder = outer
        }
    }

    /**
     * Verify issuer authenticity and the cross-envelope constraints for a compact VCDM VC.
     *
     * A bare VC is allowed only when the DCQL query explicitly disables cryptographic holder
     * binding. That switch affects the holder proof, never issuer authenticity: the compact JWS
     * is always verified through the normal identifier/trust resolution path.
     */
    private suspend fun verifyVcdmCredential(
        presentation: String,
        classification: com.sphereon.openid.oid4vc.common.vcdm.VcdmClassification?,
        issuer: CredentialIssuerRef?,
        trustedAuthentications: List<TrustedAuthenticationResolution>,
        issuerAlgAllowlist: Set<String>?,
    ): String? {
        val resolvedClassification = classification ?: return "VCDM credential classification is missing"
        val matchingTrustedAuthentications = trustedAuthentications.filter {
            it.purpose == TrustedAuthenticationPurpose.CREDENTIAL_ISSUER &&
                it.controllerClaim == CredentialIssuerControllerClaim.ISSUER &&
                it.controller == issuer?.issuer
        }
        if (matchingTrustedAuthentications.size > 1) {
            return "multiple configured issuer-authentication sources match the credential issuer"
        }
        // DIIP v5 Appendix B: a credential issued under a DID that names its Issuer's OpenID Federation
        // entity in an `OpenIDFederation` termsOfUse is admitted with that entity's `vc_issuer` keys,
        // unless the DID itself is admitted; an entity the verifier does not admit leaves the DID path.
        val federated = FederatedCredentialIssuer.applicableSources(
            issuer?.issuer, decodeJwtPayloadOrNull(presentation), trustedAuthentications,
        )
        if (federated != null && federated.sources.size > 1) {
            return "multiple configured issuer-authentication sources match federation entity '${federated.entity}'"
        }
        val configuredIssuerAuthentication = federated?.sources?.single() ?: matchingTrustedAuthentications.singleOrNull()
        val header = decodeJwtHeaderOrNull(presentation) ?: return "VCDM credential JWT header is malformed"
        val alg = header.stringClaim("alg")
        if (alg == null || alg.equals("none", ignoreCase = true)) {
            return "VCDM credential issuer JWS algorithm is missing or alg:none"
        }
        val credentialFormat = resolvedClassification.credentialFormat
        if (credentialFormat?.isJwt == true &&
            (issuerAlgAllowlist.isNullOrEmpty() || alg !in issuerAlgAllowlist)
        ) {
            return "VCDM credential issuer JWS alg '$alg' is not in the persisted verifier allowlist " +
                "for ${credentialFormat.value}: ${issuerAlgAllowlist ?: emptySet<String>()}"
        }
        val typ = header.stringClaim("typ")
        val cty = header.stringClaim("cty")
        val headerIssuer = header.stringClaim("iss")
        if (header.containsKey("typ") && typ == null) return "VCDM credential JOSE typ header is malformed"
        if (header.containsKey("cty") && cty == null) return "VCDM credential JOSE cty header is malformed"
        if (header.containsKey("iss") && headerIssuer == null) return "VCDM credential JOSE iss header is malformed"
        if (headerIssuer != null && headerIssuer != issuer?.issuer) {
            return "JOSE header iss must agree with the VCDM credential issuer"
        }
        if (resolvedClassification.document.version == VcdmVersion.V1_1 && typ != null && !typ.equals("JWT", ignoreCase = true)) {
            return "VCDM 1.1 jwt_vc_json typ must be JWT"
        }
        if (resolvedClassification.document.version == VcdmVersion.V2_0 &&
            typ != null &&
            typ !in setOf("vc+jwt", "application/vc+jwt")
        ) {
            return "VCDM 2.0 jwt_vc_json-ld typ must be vc+jwt or application/vc+jwt when present"
        }
        if (resolvedClassification.document.version == VcdmVersion.V2_0 &&
            cty !in setOf(null, "vc", "application/vc")
        ) {
            return "VCDM 2.0 jwt_vc_json-ld cty must identify a verifiable credential"
        }
        if (header.containsKey("jwk")) {
            // A JWK carried by the protected header is attacker-controlled. It is not an issuer
            // trust anchor and must never be accepted as the credential issuer key.
            return "VCDM credential issuer JWS contains an untrusted embedded jwk"
        }
        if (header.containsKey("jku") || header.containsKey("x5u")) {
            return "VCDM credential issuer JWS contains an untrusted remote key URL"
        }
        val kid = header.stringClaim("kid")
        if (header.containsKey("kid") && kid == null) return "VCDM credential JOSE kid header is malformed"
        val x5cElement = header["x5c"]
        if (x5cElement != null &&
            (x5cElement !is JsonArray || x5cElement.any { it !is JsonPrimitive || !it.isString || it.content.isBlank() })
        ) {
            return "VCDM credential issuer x5c header is malformed"
        }
        val x5c = header.stringArrayClaim("x5c").orEmpty()
        if (x5c.isNotEmpty() && configuredIssuerAuthentication?.identifier?.method != IdentifierMethodDefaults.X5C) {
            return "VCDM credential issuer x5c requires verifier-configured X.509 issuer authentication"
        }
        if (x5c.isNotEmpty() && kid != null) {
            return "VCDM credential issuer x5c cannot be combined with kid"
        }
        if (x5c.isNotEmpty()) {
            val configuredChain =
                (configuredIssuerAuthentication?.identifier?.identifier as? List<*>)
                    ?.mapNotNull { it as? String }
            if (configuredChain == null || x5c != configuredChain) {
                return "VCDM credential issuer x5c does not match the verifier-configured X.509 chain"
            }
        }
        val issuerId = issuer?.issuer
        val issuerDid = issuerId?.extractDid()
        if (issuerDid == null && configuredIssuerAuthentication == null) {
            return "non-DID VCDM credential issuer requires verifier-configured issuer authentication"
        }
        val kidDid = kid?.extractDid()
        if (issuerDid == null && kidDid != null) {
            return "VCDM credential issuer DID kid does not match the JWT iss issuer"
        }
        val trustedJwks =
            when {
                x5c.isNotEmpty() -> {
                    // The configured X.509 source is passed below. Never derive a trusted key
                    // set from the presented header itself.
                    null
                }

                issuerDid != null -> {
                    if (kid == null || kidDid != issuerDid || !kid.startsWith("$issuerDid#")) {
                        return "VCDM credential issuer kid must be an absolute DID URL for the JWT iss DID"
                    }
                    null
                }

                else -> {
                    // A non-DID kid (including a JWK thumbprint) is resolved by the configured
                    // identifier-aware JWS verifier. Do not impose a DID-only assumption here;
                    // managed keys, JWKS, X.509 and federation are external resolver concerns.
                    null
                }
            }
        // VC-JOSE-COSE section 4.2: the issuer kid is the absolute URL of the verification method that
        // signed. When the admitted source is the issuer's DID itself, verify with exactly that method
        // (already checked above to be a DID URL of the JWT iss DID), never with the document's
        // default key: a DID document can list several keys for different purposes.
        val issuerIdentifier =
            configuredIssuerAuthentication?.identifier.let { source ->
                if (source is ExternalIdentifierDidOpts && issuerDid != null && source.identifier == issuerDid &&
                    kid != null && kid.startsWith("$issuerDid#")
                ) {
                    ExternalIdentifierDidOpts(identifier = kid)
                } else {
                    source
                }
            }
        val verification =
            try {
                // The configured source is authoritative. In particular, an x5c header is only
                // accepted above when it exactly matches the admitted X.509 source; it is never
                // converted into token-controlled trust material here.
                verifyJwsCommand.execute(
                    VerifyJwsArgs(
                        jws = JwsCompact(presentation),
                        identifier = issuerIdentifier,
                        // A configured source is authoritative. In particular, never fall back to
                        // a token-supplied x5c-derived key when the verifier has admitted a peer
                        // source for this issuer.
                        trustedJwks = configuredIssuerAuthentication?.trustedJwks
                            ?: trustedJwks.takeUnless { configuredIssuerAuthentication != null },
                    ),
                )
            } catch (expected: Exception) {
                return "VCDM credential issuer JWS verification failed: ${expected.message ?: "unexpected verifier error"}"
            }
        if (verification.isErr) {
            return "VCDM credential issuer JWS verification failed: ${verification.error.message.defaultMessage}"
        }
        if (!verification.value.isValid || verification.value.cryptoVerified != true) {
            val detail = verification.value.errorMessages.takeIf { it.isNotEmpty() }?.joinToString("; ")
            return "VCDM credential issuer JWS signature result is invalid${detail?.let { ": $it" } ?: ""}"
        }
        if (verification.value.trustEstablished != true) {
            val detail = verification.value.errorMessages.takeIf { it.isNotEmpty() }?.joinToString("; ")
            return "VCDM credential issuer JWS trust result is invalid${detail?.let { ": $it" } ?: ""}"
        }

        val payload = decodeJwtPayloadOrNull(presentation) ?: return "VCDM credential JWT payload is malformed"
        return validateVcdmCredentialSemantics(payload, resolvedClassification)
    }

    /** J4: recursively verify every compact child of a secured VCDM presentation. */
    private suspend fun verifyVcdmPresentationChildren(
        artifact: String,
        classification: VcdmClassification,
        queryId: String,
        expectedNonce: String?,
        expectedAudience: String,
        verifierEncryptionJwkThumbprint: ByteArray?,
        verifierId: String?,
        dcqlQueryId: String?,
        templateId: String?,
        statusPolicy: CredentialStatusPolicy,
        trustedAuthentications: List<TrustedAuthenticationResolution>,
        verificationMethodResolutionPolicy: VerificationMethodResolutionPolicy,
        issuerAlgAllowlist: Set<String>?,
        boundHolder: String?,
        matchingQuery: DcqlCredentialQuery,
    ): VcdmVerifiedChildren {
        val state = VcdmRecursionState(matchingQuery)
        state.boundHolder = boundHolder
        state.artifacts += artifact
        state.decodedBytes = artifact.encodeToByteArray().size.toLong()
        if (state.decodedBytes > VCDM_MAX_DECODED_BYTES) {
            return VcdmVerifiedChildren(emptySet(), "maximum VCDM decoded byte size exceeded")
        }
        val error = verifyVcdmPresentationChildrenRecursive(
            classification, queryId, expectedNonce, expectedAudience, verifierEncryptionJwkThumbprint,
            verifierId, dcqlQueryId, templateId, statusPolicy, trustedAuthentications,
            verificationMethodResolutionPolicy, issuerAlgAllowlist, depth = 0, state = state,
        )
        return VcdmVerifiedChildren(state.credentialFormats, error, state.rejections.toList(), state.credentials.toList())
    }

    private suspend fun verifyVcdmPresentationChildrenRecursive(
        classification: VcdmClassification,
        queryId: String,
        expectedNonce: String?,
        expectedAudience: String,
        verifierEncryptionJwkThumbprint: ByteArray?,
        verifierId: String?,
        dcqlQueryId: String?,
        templateId: String?,
        statusPolicy: CredentialStatusPolicy,
        trustedAuthentications: List<TrustedAuthenticationResolution>,
        verificationMethodResolutionPolicy: VerificationMethodResolutionPolicy,
        issuerAlgAllowlist: Set<String>?,
        depth: Int,
        state: VcdmRecursionState,
    ): String? {
        if (depth > VCDM_MAX_RECURSION_DEPTH) return "maximum nested presentation depth exceeded"
        val childElement = classification.document.json["verifiableCredential"]
            ?: return "no verifiableCredential entry"
        if (childElement is JsonNull) return "verifiableCredential entry is null"
        val children: List<JsonElement> =
            when (classification.document.version) {
                VcdmVersion.V1_1 -> when (childElement) {
                    is JsonPrimitive -> listOf(childElement)
                    is JsonArray -> childElement
                    else -> return "malformed VCDM 1.1 verifiableCredential representation"
                }
                VcdmVersion.V2_0 -> when (childElement) {
                    is JsonArray -> childElement
                    is JsonObject -> listOf(childElement)
                    is JsonPrimitive -> return "raw JWT child is forbidden in a VCDM 2.0 presentation"
                    else -> return "malformed VCDM 2.0 verifiableCredential representation"
                }
                else -> return "unsupported VCDM presentation version"
            }
        if (children.isEmpty()) return "empty verifiableCredential collection"
        for ((index, child) in children.withIndex()) {
            if (state.nodes >= VCDM_MAX_RECURSION_NODES) return "maximum nested presentation node count exceeded"
            val failure =
                if (classification.document.version == VcdmVersion.V1_1) {
                    verifyVcdm11Child(
                        child, queryId, verifierId, dcqlQueryId, templateId, statusPolicy, trustedAuthentications,
                        verificationMethodResolutionPolicy, issuerAlgAllowlist, state,
                    )
                } else {
                    verifyVcdm2EnvelopedChild(
                        child = child,
                        queryId = queryId,
                        expectedNonce = expectedNonce,
                        expectedAudience = expectedAudience,
                        verifierEncryptionJwkThumbprint = verifierEncryptionJwkThumbprint,
                        verifierId = verifierId,
                        dcqlQueryId = dcqlQueryId,
                        templateId = templateId,
                        statusPolicy = statusPolicy,
                        trustedAuthentications = trustedAuthentications,
                        verificationMethodResolutionPolicy = verificationMethodResolutionPolicy,
                        issuerAlgAllowlist = issuerAlgAllowlist,
                        depth = depth,
                        state = state,
                    )
                }
            if (failure != null) return "verifiableCredential[$index]: $failure"
        }
        return null
    }

    private suspend fun verifyVcdm11Child(
        child: JsonElement,
        queryId: String,
        verifierId: String?,
        dcqlQueryId: String?,
        templateId: String?,
        statusPolicy: CredentialStatusPolicy,
        trustedAuthentications: List<TrustedAuthenticationResolution>,
        verificationMethodResolutionPolicy: VerificationMethodResolutionPolicy,
        issuerAlgAllowlist: Set<String>?,
        state: VcdmRecursionState,
    ): String? {
        if (child is JsonObject) {
            return verifyVcdm11DataIntegrityChild(
                child = child,
                queryId = queryId,
                verifierId = verifierId,
                dcqlQueryId = dcqlQueryId,
                templateId = templateId,
                statusPolicy = statusPolicy,
                verificationMethodResolutionPolicy = verificationMethodResolutionPolicy,
                issuerAlgAllowlist = issuerAlgAllowlist,
                state = state,
            )
        }
        val compact = (child as? JsonPrimitive)?.takeIf { it.isString }?.content
            ?: return "VCDM 1.1 child must be a secured compact jwt_vc_json string or secured JSON credential object"
        if (compact.isBlank() || !state.artifacts.add(compact)) return "duplicate or cyclic child artifact"
        state.decodedBytes += compact.encodeToByteArray().size
        if (state.decodedBytes > VCDM_MAX_DECODED_BYTES) return "maximum VCDM decoded byte size exceeded"
        state.nodes++
        val childClassification = VcdmClassifier.classifyCompactJws(compact).getOrNull()
            ?: return "malformed or unsecured VCDM 1.1 child credential"
        if (childClassification.document.version != VcdmVersion.V1_1 ||
            childClassification.document.kind != VcdmDocumentKind.CREDENTIAL
        ) return "VCDM 1.1 presentation child must be a jwt_vc_json credential"
        val failure = verifyVcdmChildCredential(
            compact,
            childClassification,
            queryId,
            verifierId,
            dcqlQueryId,
            templateId,
            statusPolicy,
            trustedAuthentications,
            issuerAlgAllowlist,
            state,
        )
        if (failure == null) state.credentialFormats += requireNotNull(childClassification.credentialFormat)
        return failure
    }

    private suspend fun verifyVcdm11DataIntegrityChild(
        child: JsonObject,
        queryId: String,
        verifierId: String?,
        dcqlQueryId: String?,
        templateId: String?,
        statusPolicy: CredentialStatusPolicy,
        verificationMethodResolutionPolicy: VerificationMethodResolutionPolicy,
        issuerAlgAllowlist: Set<String>?,
        state: VcdmRecursionState,
    ): String? {
        if (!state.artifacts.add(child.toString())) return "duplicate or cyclic child artifact"
        state.decodedBytes += child.toString().encodeToByteArray().size
        if (state.decodedBytes > VCDM_MAX_DECODED_BYTES) return "maximum VCDM decoded byte size exceeded"
        state.nodes++
        val classification = VcdmClassifier.classifyDocument(child).getOrNull()
            ?: return "malformed or unsecured VCDM 1.1 JSON child credential"
        if (classification.version != VcdmVersion.V1_1 || classification.kind != VcdmDocumentKind.CREDENTIAL) {
            return "VCDM 1.1 presentation child must be a VCDM 1.1 credential"
        }
        val controller = dataIntegrityController(child, VcdmDocumentKind.CREDENTIAL)
        val verification = try {
            vcdmDataIntegrityVerifier.verify(
                VcdmDataIntegrityVerificationArgs(
                    document = child,
                    expectedProofPurpose = ProofPurpose.ASSERTION_METHOD,
                    expectedController = controller,
                    verificationMethodResolutionPolicy = verificationMethodResolutionPolicy,
                ),
            )
        } catch (expected: Exception) {
            return "VCDM 1.1 JSON child Data Integrity verification failed: ${expected.message ?: "unexpected verifier error"}"
        }
        if (verification.isErr) return "VCDM 1.1 JSON child Data Integrity verification failed: ${verification.error.message.defaultMessage}"
        val verifiedDocument = verification.value.verifiedDocument
        validateVerifiedVcdmCredentialProfile(verifiedDocument, VcdmVersion.V1_1)?.let { return it }
        holderSubjectBindingFailure(verifiedDocument, state)?.let { return "VCDM 1.1 JSON child $it" }
        val issuer = extractDataIntegrityIssuer(child) ?: extractDataIntegrityIssuer(verifiedDocument)
        val trust = validateCredentialTrustForFormat(
            verifierId = verifierId,
            dcqlQueryId = dcqlQueryId,
            templateId = templateId,
            credentialQueryId = queryId,
            presentation = child.toString(),
            format = LDP_VC_FORMAT,
            issuer = issuer,
        )
        if (trust.enabled && trust.mode == CredentialTrustValidationMode.DEFAULT_ENFORCE && trust.trusted != true) {
            return "VCDM 1.1 JSON child trust validation failed: ${trust.details ?: trust.status ?: "issuer is not trusted"}"
        }
        val statusEvaluation =
            evaluateChildStatus(queryId, state) { evaluateCredentialStatus(credentialStatusVerifiers, verifiedDocument, statusPolicy) }
                ?: return "VCDM 1.1 JSON child status rejected"
        credentialTypeFailure(verifiedDocument, state.credentialQuery)?.let { return "VCDM 1.1 JSON child $it" }
        state.credentialFormats += CredentialFormat.LDP_VC
        state.credentials += dataIntegrityCredential(verifiedDocument, issuer, trust, statusEvaluation)
        return null
    }

    private suspend fun verifyVcdm2EnvelopedChild(
        child: JsonElement,
        queryId: String,
        expectedNonce: String?,
        expectedAudience: String,
        verifierEncryptionJwkThumbprint: ByteArray?,
        verifierId: String?,
        dcqlQueryId: String?,
        templateId: String?,
        statusPolicy: CredentialStatusPolicy,
        trustedAuthentications: List<TrustedAuthenticationResolution>,
        verificationMethodResolutionPolicy: VerificationMethodResolutionPolicy,
        issuerAlgAllowlist: Set<String>?,
        depth: Int,
        state: VcdmRecursionState,
    ): String? {
        val envelope = child as? JsonObject
            ?: return "VCDM 2.0 child must be an EnvelopedVerifiableCredential or EnvelopedVerifiablePresentation object"
        val declaredTypes = strictStringOrStringArray(envelope["type"])
        if (declaredTypes?.none { it in VCDM2_ENVELOPED_TYPES } == true) {
            return verifyDirectDataIntegrityChild(
                child = envelope,
                queryId = queryId,
                expectedNonce = expectedNonce,
                expectedAudience = expectedAudience,
                verifierEncryptionJwkThumbprint = verifierEncryptionJwkThumbprint,
                verifierId = verifierId,
                dcqlQueryId = dcqlQueryId,
                templateId = templateId,
                statusPolicy = statusPolicy,
                trustedAuthentications = trustedAuthentications,
                verificationMethodResolutionPolicy = verificationMethodResolutionPolicy,
                issuerAlgAllowlist = issuerAlgAllowlist,
                depth = depth,
                state = state,
            )
        }
        val context = strictStringOrStringArray(envelope["@context"])
            ?: return "malformed VCDM 2.0 enveloped child @context"
        if (context.firstOrNull() != VcdmProfiles.V2_0_CONTEXT) {
            return "VCDM 2.0 enveloped child has an incorrect base context"
        }
        val type = strictStringOrStringArray(envelope["type"])
            ?: return "malformed VCDM 2.0 enveloped child type"
        if (type.size != 1 || type[0] !in VCDM2_ENVELOPED_TYPES) return "unsupported VCDM 2.0 enveloped child type"
        val id = (envelope["id"] as? JsonPrimitive)?.takeIf { it.isString }?.content
            ?: return "malformed VCDM 2.0 enveloped child id"
        val prefix = if (type[0] == VCDM2_ENVELOPED_VC_TYPE) VCDM2_VC_DATA_URI_PREFIX else VCDM2_VP_DATA_URI_PREFIX
        if (!id.startsWith(prefix)) return "VCDM 2.0 enveloped child id has an incorrect media type"
        val compact = id.removePrefix(prefix).takeIf { it.isNotBlank() }
            ?: return "empty VCDM 2.0 enveloped child artifact"
        if (!state.artifacts.add(id) || !state.artifacts.add(compact)) return "duplicate or cyclic child artifact"
        state.decodedBytes += compact.encodeToByteArray().size
        if (state.decodedBytes > VCDM_MAX_DECODED_BYTES) return "maximum VCDM decoded byte size exceeded"
        state.nodes++
        val childClassification = VcdmClassifier.classifyCompactJws(compact).getOrNull()
            ?: return "malformed or unsecured VCDM 2.0 enveloped child"
        if (childClassification.document.version != VcdmVersion.V2_0) return "VCDM 2.0 enveloped child has the wrong VCDM version"
        if (type[0] == VCDM2_ENVELOPED_VC_TYPE) {
            if (childClassification.document.kind != VcdmDocumentKind.CREDENTIAL) {
                return "EnvelopedVerifiableCredential must contain a VCDM credential"
            }
            val failure = verifyVcdmChildCredential(
                compact,
                childClassification,
                queryId,
                verifierId,
                dcqlQueryId,
                templateId,
                statusPolicy,
                trustedAuthentications,
                issuerAlgAllowlist,
                state,
            )
            if (failure == null) state.credentialFormats += requireNotNull(childClassification.credentialFormat)
            return failure
        }
        if (childClassification.document.kind != VcdmDocumentKind.PRESENTATION) return "EnvelopedVerifiablePresentation must contain a VCDM presentation"
        return verifyNestedVcdmPresentation(
            compact, childClassification, queryId, expectedNonce, expectedAudience, verifierEncryptionJwkThumbprint,
            verifierId, dcqlQueryId, templateId, statusPolicy, trustedAuthentications,
            verificationMethodResolutionPolicy, issuerAlgAllowlist, depth + 1, state,
        )
    }

    private suspend fun verifyDirectDataIntegrityChild(
        child: JsonObject,
        queryId: String,
        expectedNonce: String?,
        expectedAudience: String,
        verifierEncryptionJwkThumbprint: ByteArray?,
        verifierId: String?,
        dcqlQueryId: String?,
        templateId: String?,
        statusPolicy: CredentialStatusPolicy,
        trustedAuthentications: List<TrustedAuthenticationResolution>,
        verificationMethodResolutionPolicy: VerificationMethodResolutionPolicy,
        issuerAlgAllowlist: Set<String>?,
        depth: Int,
        state: VcdmRecursionState,
    ): String? {
        val artifact = child.toString()
        if (!state.artifacts.add(artifact)) return "duplicate or cyclic direct Data Integrity child"
        state.decodedBytes += artifact.encodeToByteArray().size
        if (state.decodedBytes > VCDM_MAX_DECODED_BYTES) return "maximum VCDM decoded byte size exceeded"
        if (state.nodes >= VCDM_MAX_RECURSION_NODES) return "maximum nested presentation node count exceeded"
        state.nodes++
        val classification = VcdmClassifier.classifyDocument(child)
            .getOrElse { return "direct Data Integrity child classification failed: ${it.message.defaultMessage}" }
        if (classification.version != VcdmVersion.V2_0) return "direct Data Integrity child has the wrong VCDM version"
        val controller = dataIntegrityController(child, classification.kind)
        val verification =
            try {
                vcdmDataIntegrityVerifier.verify(
                    VcdmDataIntegrityVerificationArgs(
                        document = child,
                        expectedProofPurpose = if (classification.kind == VcdmDocumentKind.CREDENTIAL) {
                            ProofPurpose.ASSERTION_METHOD
                        } else {
                            ProofPurpose.AUTHENTICATION
                        },
                        expectedController = controller,
                        expectedDomain = if (classification.kind == VcdmDocumentKind.PRESENTATION) expectedAudience else null,
                        expectedChallenge = if (classification.kind == VcdmDocumentKind.PRESENTATION) expectedNonce else null,
                        requireDomainAndChallenge = classification.kind == VcdmDocumentKind.PRESENTATION,
                        verificationMethodResolutionPolicy = verificationMethodResolutionPolicy,
                    ),
                )
            } catch (expected: Exception) {
                return "direct Data Integrity child verification failed: ${expected.message ?: "unexpected verifier error"}"
            }
        if (verification.isErr) {
            return "direct Data Integrity child verification failed: ${verification.error.message.defaultMessage}"
        }
        if (classification.kind == VcdmDocumentKind.CREDENTIAL) {
            validateVerifiedVcdmCredentialProfile(
                verification.value.verifiedDocument,
                VcdmVersion.V2_0,
            )?.let { return it }
        }
        if (classification.kind == VcdmDocumentKind.PRESENTATION &&
            classification.version == VcdmVersion.V2_0 &&
            controller == null &&
            verification.value.authenticatedControllers.isEmpty()
        ) {
            return "direct Data Integrity holderless VCDM 2.0 presentation requires an authenticated controller"
        }
        val verifiedChild = verification.value.verifiedDocument
        if (classification.kind == VcdmDocumentKind.CREDENTIAL) {
            holderSubjectBindingFailure(verifiedChild, state)?.let { return "direct Data Integrity child $it" }
        }
        if (classification.kind == VcdmDocumentKind.PRESENTATION) {
            return state.withPresentationHolder(controller ?: verification.value.authenticatedControllers.singleOrNull()) {
                verifyDataIntegrityPresentationChildren(
                document = verifiedChild,
                queryId = queryId,
                expectedDomain = expectedAudience,
                expectedChallenge = expectedNonce,
                expectedAudience = expectedAudience,
                verifierEncryptionJwkThumbprint = verifierEncryptionJwkThumbprint,
                verifierId = verifierId,
                dcqlQueryId = dcqlQueryId,
                templateId = templateId,
                statusPolicy = statusPolicy,
                trustedAuthentications = trustedAuthentications,
                verificationMethodResolutionPolicy = verificationMethodResolutionPolicy,
                issuerAlgAllowlist = issuerAlgAllowlist,
                depth = depth + 1,
                state = state,
            )
            }
        }

        val issuer = extractDataIntegrityIssuer(child) ?: extractDataIntegrityIssuer(verifiedChild)
        val trust = validateCredentialTrustForFormat(
            verifierId = verifierId,
            dcqlQueryId = dcqlQueryId,
            templateId = templateId,
            credentialQueryId = queryId,
            presentation = JSON_LENIENT.encodeToString(JsonElement.serializer(), child),
            format = LDP_VC_FORMAT,
            issuer = issuer,
        )
        if (trust.enabled && trust.mode == CredentialTrustValidationMode.DEFAULT_ENFORCE && trust.trusted != true) {
            return "direct Data Integrity child trust validation failed: ${trust.details ?: trust.status ?: "issuer is not trusted"}"
        }
        val statusEvaluation =
            evaluateChildStatus(queryId, state) { evaluateCredentialStatus(credentialStatusVerifiers, verifiedChild, statusPolicy) }
                ?: return "direct Data Integrity child status rejected"
        if (classification.kind == VcdmDocumentKind.CREDENTIAL) {
            credentialTypeFailure(verifiedChild, state.credentialQuery)?.let { return "direct Data Integrity child $it" }
            state.credentialFormats += CredentialFormat.LDP_VC
            state.credentials += dataIntegrityCredential(verifiedChild, issuer, trust, statusEvaluation)
        }
        return null
    }

    /**
     * Cryptographic success does not make an arbitrary JSON object a VC. Validate the document
     * returned by the DI verifier against the profile selected by its authenticated VCDM version
     * before trust/status evaluation or child-format accounting.
     */
    private fun validateVerifiedVcdmCredentialProfile(
        document: JsonObject,
        version: VcdmVersion,
    ): String? {
        val validation = when (version) {
            VcdmVersion.V1_1 -> VcdmProfiles.v1_1.validateCredential(document)
            VcdmVersion.V2_0 -> VcdmProfiles.v2_0.validateCredential(document)
            else -> return "unsupported VCDM version '${version.value}' for Data Integrity credential profile validation"
        }
        if (validation.valid) return null
        return "VCDM ${version.value} Data Integrity credential profile validation failed: " +
            validation.errors.joinToString("; ") { it.message.defaultMessage }
    }

    private suspend fun verifyNestedVcdmPresentation(
        compact: String,
        classification: VcdmClassification,
        queryId: String,
        expectedNonce: String?,
        expectedAudience: String,
        verifierEncryptionJwkThumbprint: ByteArray?,
        verifierId: String?,
        dcqlQueryId: String?,
        templateId: String?,
        statusPolicy: CredentialStatusPolicy,
        trustedAuthentications: List<TrustedAuthenticationResolution>,
        verificationMethodResolutionPolicy: VerificationMethodResolutionPolicy,
        issuerAlgAllowlist: Set<String>?,
        depth: Int,
        state: VcdmRecursionState,
    ): String? {
        if (depth > VCDM_MAX_RECURSION_DEPTH) return "maximum nested presentation depth exceeded"
        val resolvedExpectedNonce = expectedNonce ?: return "nested VCDM presentation expected nonce is missing"
        val holderBinding =
            try {
                verifyHolderBindingCommand.execute(
                    VerifyHolderBindingArgs(
                        presentation = compact,
                        presentationFormat = classification.presentationFormat,
                        expectedNonce = resolvedExpectedNonce,
                        expectedAudience = expectedAudience,
                        requireCryptographicHolderBinding = true,
                        trustedAuthentications = trustedAuthentications,
                        clientId = expectedAudience,
                        responseUri = null,
                        verifierEncryptionJwkThumbprint = verifierEncryptionJwkThumbprint,
                    ),
                )
            } catch (expected: Exception) {
                return "nested VCDM presentation holder verification failed: ${expected.message ?: "unexpected verifier error"}"
            }
        if (holderBinding.isErr) return "nested VCDM presentation holder verification failed: ${holderBinding.error.message.defaultMessage}"
        if (!holderBinding.value.verified) return "nested VCDM presentation nonce/audience binding failed"
        return state.withPresentationHolder(compactPresentationHolder(classification)) {
            verifyVcdmPresentationChildrenRecursive(
                classification, queryId, expectedNonce, expectedAudience, verifierEncryptionJwkThumbprint,
                verifierId, dcqlQueryId, templateId, statusPolicy, trustedAuthentications,
                verificationMethodResolutionPolicy, issuerAlgAllowlist, depth, state,
            )
        }
    }

    private suspend fun verifyVcdmChildCredential(
        compact: String,
        classification: VcdmClassification,
        queryId: String,
        verifierId: String?,
        dcqlQueryId: String?,
        templateId: String?,
        statusPolicy: CredentialStatusPolicy,
        trustedAuthentications: List<TrustedAuthenticationResolution>,
        issuerAlgAllowlist: Set<String>?,
        state: VcdmRecursionState,
    ): String? {
        val format = requireNotNull(classification.credentialFormat)
        val issuer = withFederationEntity(extractCredentialIssuer(compact, format), compact, trustedAuthentications)
        // Verify the child issuer proof before invoking trust or status callbacks. The outer VP
        // holder is never reused as an issuer for this child.
        verifyVcdmCredential(compact, classification, issuer, trustedAuthentications, issuerAlgAllowlist)?.let { return "child credential rejected: $it" }
        val vcJoseConfirmation =
            if (classification.document.version == VcdmVersion.V2_0) listOf(classification.rawPayload, classification.protectedHeader) else emptyList()
        holderSubjectBindingFailure(classification.document.json, state, vcJoseConfirmation)?.let { return "child credential rejected: $it" }
        val trust = validateCredentialTrust(
            verifierId, dcqlQueryId, templateId, queryId, compact, format, issuer,
        )
        if (trust.enabled && trust.mode == CredentialTrustValidationMode.DEFAULT_ENFORCE && trust.trusted != true) {
            return "child credential trust validation failed: ${trust.details ?: trust.status ?: "issuer is not trusted"}"
        }
        val statusEvaluation =
            evaluateChildStatus(queryId, state) { evaluateCredentialStatus(credentialStatusVerifiers, (credentialStatusInputFor(compact, format) ?: CredentialStatusInput()), statusPolicy) }
                ?: return "child credential status rejected"
        credentialTypeFailure(classification.document.json, state.credentialQuery)?.let { return "child credential rejected: $it" }
        state.credentials +=
            VerifiedVcdmCredential(
                document = classification.document.json,
                format = format,
                issuer = issuer,
                trust = trust,
                statusEvaluation = statusEvaluation,
                temporalFacts = verifiedCredentialTemporalFacts(classification.rawPayload, vcdm = true),
            )
        return null
    }

    /** VCDM permits both a single string and an array of strings for @context and type. */
    private fun strictStringOrStringArray(element: JsonElement?): List<String>? =
        when (element) {
            is JsonPrimitive -> element.takeIf { it.isString && it.content.isNotBlank() }?.let { listOf(it.content) }
            is JsonArray -> element.takeIf { it.isNotEmpty() }?.map { item ->
                (item as? JsonPrimitive)?.takeIf { it.isString && it.content.isNotBlank() }?.content ?: return null
            }
            else -> null
        }

    private data class VcdmVerifiedChildren(
        val credentialFormats: Set<CredentialFormat>,
        val error: String? = null,
        /** Typed status rejections collected from nested children, under the parent query identity. */
        val rejections: List<CredentialValidationRejection> = emptyList(),
        /** Every child credential that passed all of its own checks, in presentation order. */
        val credentials: List<VerifiedVcdmCredential> = emptyList(),
    )

    /** A credential inside a W3C presentation that passed its own proof, trust and status checks. */
    private class VerifiedVcdmCredential(
        val document: JsonObject,
        val format: CredentialFormat,
        val issuer: CredentialIssuerRef?,
        val trust: CredentialTrustValidation,
        val statusEvaluation: CredentialStatusEvaluation,
        val temporalFacts: VerifiedCredentialTemporalFacts?,
    )

    private class VcdmRecursionState(
        /** The query every credential in the presentation must satisfy on its own. */
        val credentialQuery: DcqlCredentialQuery,
    ) {
        /**
         * The DID holder of the presentation whose credentials are being verified, when that
         * presentation must carry Cryptographic Holder Binding; null when no subject binding applies.
         */
        var boundHolder: String? = null
        val artifacts: MutableSet<String> = mutableSetOf()
        val rejections: MutableList<CredentialValidationRejection> = mutableListOf()
        val credentialFormats: MutableSet<CredentialFormat> = linkedSetOf()
        val credentials: MutableList<VerifiedVcdmCredential> = mutableListOf()
        var nodes: Int = 1
        var decodedBytes: Long = 0
    }

    private fun validateVcdmCredentialSemantics(
        payload: JsonObject,
        classification: com.sphereon.openid.oid4vc.common.vcdm.VcdmClassification,
    ): String? {
        val profile = if (classification.document.version == VcdmVersion.V1_1) VcdmProfiles.v1_1 else VcdmProfiles.v2_0
        val profileResult = profile.validateCredential(classification.document.json)
        if (!profileResult.valid) {
            return profileResult.errors.firstOrNull()?.message?.defaultMessage
                ?: "VCDM credential profile validation failed"
        }

        val vc = payload["vc"] as? JsonObject
        val issuerElement =
            if (classification.document.version == VcdmVersion.V1_1) {
                // In jwt_vc_json the issuer is represented by the registered JWT `iss` claim;
                // an optional vc.issuer must agree with it when present.
                vc?.get("issuer") ?: payload["iss"] ?: return "VCDM 1.1 credential issuer is required"
            } else {
                payload["issuer"] ?: return "VCDM 2.0 credential issuer is required"
            }
        val issuer = issuerIdentifier(issuerElement)
            ?: return "VCDM credential issuer must be a string or an object with a string id"
        if (!VcdmUris.isValid(issuer)) return "VCDM credential issuer must be a URI"

        val iss = payload["iss"]?.stringJsonClaim("iss")
        if (classification.document.version == VcdmVersion.V1_1 && iss == null) {
            return "VCDM 1.1 credential JWT iss claim is required and must be a string"
        }
        if (payload.containsKey("iss") && iss == null) return "JWT iss must be a string"
        if (iss != null && iss != issuer) return "JWT iss must agree with the VCDM credential issuer"

        val idElement = if (classification.document.version == VcdmVersion.V1_1) vc?.get("id") else payload["id"]
        val jti =
            if (payload.containsKey("jti")) {
                payload["jti"]?.stringJsonClaim("jti") ?: return "JWT jti must be a string"
            } else {
                null
            }
        val id = idElement?.stringJsonClaim("id")
        if (idElement != null && id == null) return "VCDM credential id must be a string"
        if (id != null && !VcdmUris.isValid(id)) return "VCDM credential id must be a URI"
        if (jti != null && id != null && jti != id) return "JWT jti must agree with the VCDM credential id"

        val subjectElement =
            if (classification.document.version == VcdmVersion.V1_1) vc?.get("credentialSubject")
            else payload["credentialSubject"]
        val subjectIds = validateCredentialSubjects(subjectElement)
            ?: return "VCDM credentialSubject is malformed"
        val sub = payload["sub"]?.stringJsonClaim("sub")
            ?: if (payload.containsKey("sub")) return "JWT sub must be a string" else null
        if (sub != null && (subjectIds.size != 1 || subjectIds.single() != sub)) {
            return "JWT sub must agree with one unambiguous credentialSubject.id"
        }

        val temporalFailure = validateCredentialTemporalClaims(payload, vc, classification.document.version)
        if (temporalFailure != null) return temporalFailure
        return null
    }

    private fun validateCredentialSubjects(
        element: JsonElement?,
    ): List<String>? {
        val subjects =
            when (element) {
                is JsonObject -> listOf(element)
                is JsonArray -> element.map { it as? JsonObject ?: return null }
                else -> return null
            }
        if (subjects.isEmpty()) return null
        val ids = mutableListOf<String>()
        for (subject in subjects) {
            val id = subject["id"]
            if (id != null) {
                val value = (id as? JsonPrimitive)?.takeIf { it.isString }?.content ?: return null
                if (!VcdmUris.isValid(value)) return null
                ids += value
            }
        }
        return if (subjects.size == 1 && ids.size == 1) ids else emptyList()
    }

    private fun validateCredentialTemporalClaims(
        payload: JsonObject,
        vc: JsonObject?,
        version: VcdmVersion,
    ): String? {
        val body = if (version == VcdmVersion.V1_1) vc else payload
        val fromName = if (version == VcdmVersion.V1_1) "issuanceDate" else "validFrom"
        val untilName = if (version == VcdmVersion.V1_1) "expirationDate" else "validUntil"
        val from = body?.get(fromName)?.let { parseInstantClaim(it, fromName) }
        if (from is TemporalParseFailure) return from.message
        val until = body?.get(untilName)?.let { parseInstantClaim(it, untilName) }
        if (until is TemporalParseFailure) return until.message
        val fromInstant = (from as? TemporalInstant)?.value
        val untilInstant = (until as? TemporalInstant)?.value
        if (fromInstant != null && untilInstant != null && fromInstant > untilInstant) {
            return "$fromName must not be after $untilName"
        }
        val now = Clock.System.now()
        if (fromInstant != null && now < fromInstant) {
            // VCDM 2.0 explicitly permits a credential to become valid in the future.  This is
            // not a malformed document or failed proof; it is a consuming-layer effective-time
            // policy result. Keep the legacy wording for callers that key off it, while making
            // the distinction explicit in the returned verifier diagnostic.
            return if (version == VcdmVersion.V2_0) {
                "VCDM credential is not yet effective (not yet valid: $fromName is in the future); " +
                    "credential structure and issuer proof remain valid"
            } else {
                "VCDM credential is not yet valid ($fromName is in the future)"
            }
        }
        if (untilInstant != null && now > untilInstant) return "VCDM credential is expired ($untilName is in the past)"

        // Parse each optional claim independently. An absent claim must not return from this
        // function: doing so would skip validation of a later iat/exp claim (the usual VCDM 2
        // profile has iat/exp without nbf).
        val iat = if (payload.containsKey("iat")) {
            parseNumericClaim(payload["iat"], "iat")
                ?: return "JWT iat must be a finite JSON number"
        } else {
            null
        }
        val nbf = if (payload.containsKey("nbf")) {
            parseNumericClaim(payload["nbf"], "nbf")
                ?: return "JWT nbf must be a finite JSON number"
        } else {
            null
        }
        val exp = if (payload.containsKey("exp")) {
            parseNumericClaim(payload["exp"], "exp")
                ?: return "JWT exp must be a finite JSON number"
        } else {
            null
        }
        // RFC 7519 gives iat, nbf, and exp independent meanings. A credential can be signed
        // after its validity has already begun, so nbf earlier than iat is conforming.
        val nowSeconds = now.epochSeconds.toDouble()
        if (iat != null && iat > nowSeconds) return "VCDM credential is not yet valid (iat is in the future)"
        if (nbf != null && nbf > nowSeconds) return "VCDM credential is not yet valid (nbf is in the future)"
        if (exp != null && exp <= nowSeconds) return "VCDM credential is expired (exp is not in the future)"
        return null
    }

    private fun parseInstantClaim(element: JsonElement, name: String): TemporalClaim {
        val primitive = element as? JsonPrimitive
        if (primitive == null || !primitive.isString) return TemporalParseFailure("$name must be an ISO-8601 date-time string")
        return try {
            TemporalInstant(Instant.parse(primitive.content))
        } catch (_: IllegalArgumentException) {
            TemporalParseFailure("$name is not a valid ISO-8601 date-time")
        }
    }

    private fun parseNumericClaim(element: JsonElement?, name: String): Double? {
        if (element == null) return null
        val primitive = element as? JsonPrimitive ?: return null
        if (primitive.isString) return null
        return primitive.doubleOrNull?.takeIf { it.isFinite() }
    }

    private fun issuerIdentifier(element: JsonElement): String? =
        when (element) {
            is JsonPrimitive -> element.takeIf { it.isString }?.content
            is JsonObject -> (element["id"] as? JsonPrimitive)?.takeIf { it.isString }?.content
            else -> null
        }

    private fun JsonElement.stringJsonClaim(name: String): String? =
        (this as? JsonPrimitive)?.takeIf { it.isString }?.content

    private sealed interface TemporalClaim
    private data class TemporalInstant(val value: Instant) : TemporalClaim
    private data class TemporalParseFailure(val message: String) : TemporalClaim


    private fun decodeJwtPayloadOrNull(presentation: String): JsonObject? {
        val parts = presentation.split(".")
        if (parts.size != 3) return null
        val bytes =
            try {
                parts[1].decodeFromBase64Url()
            } catch (expected: IllegalArgumentException) {
                return null
            }
        val parsed =
            try {
                JSON_LENIENT.parseToJsonElement(bytes.decodeToString())
            } catch (expected: kotlinx.serialization.SerializationException) {
                return null
            }
        return parsed as? JsonObject
    }

    private fun referencesVcdm2Context(context: kotlinx.serialization.json.JsonElement): Boolean {
        val target = WellKnownContexts.VCDM_2_0
        return when (context) {
            is JsonPrimitive -> context.isString && context.content == target
            is JsonArray -> context.any { (it as? JsonPrimitive)?.let { p -> p.isString && p.content == target } == true }
            else -> false
        }
    }

    private fun primaryCredentialTypeOrNull(payload: JsonObject): String? {
        val types = (payload["type"] as? JsonArray) ?: return null
        val stringTypes = types.mapNotNull { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content }
        return stringTypes.firstOrNull { it != WellKnownCredentialTypes.VERIFIABLE_CREDENTIAL }
            ?: stringTypes.firstOrNull()
    }

    private fun formatJsonLdError(error: JsonLdError): String = "${error.code}: ${error.message.defaultMessage}"

    /**
     * Extract the claims of the credentials in a presentation, typed as they were issued.
     *
     * - SD-JWT: parses the compact serialization and resolves all disclosures. One projection.
     * - mso_mdoc: CBOR-decodes the `DeviceResponse` and reports each document on its own, with every
     *   disclosed `IssuerSignedItem` converted to JSON from its original CBOR.
     *
     * Claim-key shape: mdoc data elements are namespace-qualified, so keys are
     * `<namespace>.<elementIdentifier>` (e.g. `org.iso.18013.5.1.given_name`). This mirrors the
     * mdoc DCQL `claims[].path` representation `[namespace, elementIdentifier]` (a two-segment
     * path joined by `.`), keeping the verifier's normalized claims map aligned with the query
     * paths used to request them.
     *
     * A presentation whose claims cannot be read is an error, never an empty claims map.
     */
    internal fun extractClaimProjections(
        presentation: String,
        format: CredentialFormat,
    ): IdkResult<List<CredentialClaimProjection>, IdkError> =
        when (format) {
            CredentialFormat.SD_JWT_VC, CredentialFormat.W3C_VC_SD_JWT ->
                SdJwtCodec.parse(presentation).map { sdJwt -> listOf(sdJwtClaimProjection(sdJwt.payload.fullPayload)) }

            CredentialFormat.MSO_MDOC -> mdocClaimProjections(presentation)

            else -> Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Claim extraction is not supported for format ${format.value}"))
        }

    /**
     * Full credential payload (including the `status` / `credentialStatus` claims that
     * the reported claims deliberately leave out) for status-list verification. SD-JWT → the
     * resolved full payload; compact JWT-VC → the decoded JWT body; mdoc → a metadata-only status
     * reference extracted from the authenticated MSO (never a disclosed namespace claim).
     */
    private fun credentialStatusInputFor(
        presentation: String,
        format: CredentialFormat,
        mdocAuthentications: List<TrustedAuthenticationResolution> = emptyList(),
    ): CredentialStatusInput? =
        when (format) {
            CredentialFormat.SD_JWT_VC, CredentialFormat.W3C_VC_SD_JWT -> {
                SdJwtCodec
                    .parse(presentation)
                    .getOrNull()
                    ?.payload
                    ?.fullPayload
                    ?.let { CredentialStatusInput(claims = it) }
            }

            CredentialFormat.JWT_VC_JSON, CredentialFormat.JWT_VC_JSON_LD -> {
                decodeJwtPayloadOrNull(presentation)?.let { CredentialStatusInput(claims = it) }
            }

            CredentialFormat.MSO_MDOC -> {
                extractMdocStatusMetadata(presentation, mdocAuthentications)?.let { metadata ->
                    CredentialStatusInput(metadata = metadata)
                }
            }

            else -> {
                null
            }
        }

    /**
     * Adapt the status reference carried by an authenticated MSO to the common status verifier
     * claim shape. This is deliberately metadata-only: MSO status never becomes an ordinary
     * disclosed namespace claim.
     */
    private fun extractMdocStatusMetadata(presentation: String, authentications: List<TrustedAuthenticationResolution>): CredentialStatusMetadata? {
        val deviceResponseBytes = runCatching { presentation.decodeFromBase64Url() }.getOrNull() ?: return null
        val response = deviceResponseCborCodec.decode(deviceResponseBytes).getOrNull()?.value ?: return null
        val statuses = response.documents
            ?.asSequence()
            ?.mapNotNull { document ->
                val payload = document.issuerSigned.issuerAuth.payload?.value ?: return@mapNotNull null
                mobileSecurityObjectCborCodec.decode(payload).getOrNull()?.value?.status?.let { it to document.docType.toString() }
            }
            ?.toList()
            .orEmpty()
        if (statuses.isEmpty()) return null
        val references = statuses.flatMap { (status, documentType) ->
            val trustAnchors = mdocStatusTrustAnchors(authentications, documentType)
            buildList {
                status.statusList?.let { statusList ->
                    add(
                        CredentialStatusReference(
                            mechanism = "mdoc_status",
                            uri = statusList.uri,
                            // `idx` is an unsigned ISO value. Do not let a value larger than
                            // Int.MAX_VALUE wrap into a valid-looking negative/low index.
                            index = if (statusList.idx <= Int.MAX_VALUE.toUInt()) statusList.idx.toInt() else -1,
                            certificate = statusList.certificate,
                            trustedCertificates = trustAnchors,
                        ),
                    )
                }
                status.identifierList?.let { identifierList ->
                    add(
                        CredentialStatusReference(
                            mechanism = "mdoc_status",
                            uri = identifierList.uri,
                            index = 0,
                            identifier = identifierList.id,
                            certificate = identifierList.certificate,
                            trustedCertificates = trustAnchors,
                        ),
                    )
                }
            }
        }
        return CredentialStatusMetadata(MdocCredentialStatusMetadata(references))
    }

    private fun CredentialStatusInput?.hasMdocStatusReference(): Boolean =
        this?.metadata?.mdoc?.references?.any { it.mechanism == "mdoc_status" } == true

    private suspend fun validateCredentialTrust(
        verifierId: String?,
        dcqlQueryId: String?,
        templateId: String?,
        credentialQueryId: String,
        presentation: String,
        detectedFormat: CredentialFormat,
        issuer: CredentialIssuerRef?,
    ): CredentialTrustValidation {
        return validateCredentialTrustForFormat(
            verifierId = verifierId,
            dcqlQueryId = dcqlQueryId,
            templateId = templateId,
            credentialQueryId = credentialQueryId,
            presentation = presentation,
            format = detectedFormat.value,
            issuer = issuer,
        )
    }

    /**
     * A DeviceResponse may carry more than one mdoc. The issuer metadata used for trust must be
     * checked for every clear document; validating only the first document would let a trusted
     * first mdoc hide an untrusted second issuer in the same response.
     */
    private suspend fun validateMdocTrustForAllDocuments(
        verifierId: String?,
        dcqlQueryId: String?,
        templateId: String?,
        credentialQueryId: String,
        presentation: String,
        firstIssuer: CredentialIssuerRef?,
    ): CredentialTrustValidation {
        val issuers = extractMdocIssuers(presentation)
        if (issuers.isEmpty()) {
            return validateCredentialTrustForFormat(
                verifierId = verifierId,
                dcqlQueryId = dcqlQueryId,
                templateId = templateId,
                credentialQueryId = credentialQueryId,
                presentation = presentation,
                format = CredentialFormat.MSO_MDOC.value,
                issuer = firstIssuer,
            )
        }
        var firstValidation: CredentialTrustValidation? = null
        for (issuer in issuers) {
            val validation = validateCredentialTrustForFormat(
                verifierId = verifierId,
                dcqlQueryId = dcqlQueryId,
                templateId = templateId,
                credentialQueryId = credentialQueryId,
                presentation = presentation,
                format = CredentialFormat.MSO_MDOC.value,
                issuer = issuer,
            )
            firstValidation = firstValidation ?: validation
            if (validation.enabled &&
                validation.mode == CredentialTrustValidationMode.DEFAULT_ENFORCE &&
                validation.trusted != true
            ) {
                return validation
            }
        }
        return requireNotNull(firstValidation)
    }

    private suspend fun validateCredentialTrustForFormat(
        verifierId: String?,
        dcqlQueryId: String?,
        templateId: String?,
        credentialQueryId: String,
        presentation: String,
        format: String,
        issuer: CredentialIssuerRef?,
    ): CredentialTrustValidation {
        val validationArgs =
            Oid4vpCredentialTrustValidationArgs(
                verifierId = verifierId,
                dcqlQueryId = dcqlQueryId,
                templateId = templateId,
                credentialQueryId = credentialQueryId,
                format = format,
                presentation = presentation,
                issuer = issuer,
            )
        val validator =
            credentialTrustValidators.firstOrNull { it.supports(validationArgs) }
                ?: return CredentialTrustValidation(
                    enabled = false,
                    mode = CredentialTrustValidationMode.DISABLED,
                    details = "No OID4VP credential trust validator configured",
                )

        return validator.validate(validationArgs).getOrElse { error ->
            CredentialTrustValidation(
                enabled = true,
                trusted = false,
                mode = CredentialTrustValidationMode.DEFAULT_ENFORCE,
                status = "VALIDATION_ERROR",
                details = error.message.defaultMessage,
            )
        }
    }

    private fun extractCredentialIssuer(
        presentation: String,
        format: CredentialFormat,
    ): CredentialIssuerRef? =
        when (format) {
            CredentialFormat.SD_JWT_VC, CredentialFormat.W3C_VC_SD_JWT -> {
                val issuerJwt = presentation.substringBefore("~").takeIf { it.contains(".") }
                issuerJwt?.let(::extractJwtIssuer)
            }

            CredentialFormat.JWT_VC_JSON, CredentialFormat.JWT_VC_JSON_LD -> {
                extractJwtIssuer(presentation)
            }

            CredentialFormat.MSO_MDOC -> {
                extractMdocIssuer(presentation)
            }

            else -> {
                null
            }
        }

    /**
     * For a credential issued under a DID that is verified with the `vc_issuer` keys of the OpenID
     * Federation entity it names (DIIP v5, Appendix B), the trust evidence is that entity: it is the
     * admitted controller, while the credential keeps its DID as issuer. Any other credential keeps its
     * extracted issuer reference.
     */
    private fun withFederationEntity(
        issuer: CredentialIssuerRef?,
        compact: String,
        trustedAuthentications: List<TrustedAuthenticationResolution>,
    ): CredentialIssuerRef? {
        val ref = issuer ?: return null
        val federated = FederatedCredentialIssuer.applicableSources(
            ref.issuer, decodeJwtPayloadOrNull(compact.substringBefore('~')), trustedAuthentications,
        ) ?: return ref
        // Without exactly one admitted source the credential has already failed issuer verification.
        if (federated.sources.size != 1) return ref
        return ref.copy(method = FEDERATION_ISSUER_METHOD, oidfedEntityId = federated.entity)
    }

    private fun extractDataIntegrityIssuer(document: JsonObject): CredentialIssuerRef? {
        val issuerElement = document["issuer"]
            ?: (document["vc"] as? JsonObject)?.get("issuer")
        val issuer = when (val element = issuerElement) {
            is JsonPrimitive -> element.takeIf { it.isString }?.content
            is JsonObject -> (element["id"] as? JsonPrimitive)?.takeIf { it.isString }?.content
            else -> null
        } ?: return null
        val did = issuer.extractDid()
        return CredentialIssuerRef(
            issuer = issuer,
            method = if (did != null) "did" else null,
            did = did,
        )
    }

    private fun extractJwtIssuer(compactJwt: String): CredentialIssuerRef? {
        val header = decodeJwtHeaderOrNull(compactJwt)
        val payload = decodeJwtPayloadOrNull(compactJwt)
        if (header == null && payload == null) return null

        val issuer = payload?.stringClaim("iss") ?: payload?.vcIssuer()
        val kid = header?.stringClaim("kid")
        val x5c = header?.stringArrayClaim("x5c").orEmpty()
        val did = issuer?.extractDid() ?: kid?.extractDid()
        // An https `iss` alone is an issuer URI. It is only a federation entity when the issuer
        // JWT carries the OpenID Federation `trust_chain` header proving the entity statements.
        val hasFederationTrustChain = header?.stringArrayClaim("trust_chain").orEmpty().isNotEmpty()
        val oidfedEntityId = issuer?.takeIf { hasFederationTrustChain && it.isHttpUrl() }
        val method =
            when {
                x5c.isNotEmpty() -> "x509"
                did != null -> "did"
                oidfedEntityId != null -> FEDERATION_ISSUER_METHOD
                issuer?.isHttpUrl() == true -> "issuer_uri"
                else -> null
            }
        return CredentialIssuerRef(
            issuer = issuer,
            method = method,
            did = did,
            oidfedEntityId = oidfedEntityId,
            kid = kid,
            x5c = x5c,
        )
    }

    private fun extractMdocIssuer(presentation: String): CredentialIssuerRef? {
        return extractMdocIssuers(presentation).firstOrNull()
    }

    private fun extractMdocIssuers(presentation: String): List<CredentialIssuerRef> {
        val deviceResponseBytes =
            try {
                presentation.decodeFromBase64Url()
            } catch (_: IllegalArgumentException) {
                return emptyList()
            }
        val deviceResponse =
            deviceResponseCborCodec.decode(deviceResponseBytes).getOrNull()?.value ?: return emptyList()
        return deviceResponse.documents.orEmpty().map { document ->
            val issuerAuth = document.issuerSigned.issuerAuth
            val x5chain = issuerAuth.protectedHeader.x5chain ?: issuerAuth.unprotectedHeader?.x5chain
            val x5c = x5chain?.value?.map { it.value.encodeTo(Encoding.BASE64) }.orEmpty()
            CredentialIssuerRef(
                issuer = document.docType.toString(),
                method = if (x5c.isNotEmpty()) "x509" else null,
                x5c = x5c,
                docType = document.docType.toString(),
            )
        }
    }

    private fun decodeJwtHeaderOrNull(presentation: String): JsonObject? {
        val parts = presentation.split(".")
        if (parts.size != 3) return null
        val bytes =
            try {
                parts[0].decodeFromBase64Url()
            } catch (_: IllegalArgumentException) {
                return null
            }
        val parsed =
            try {
                JSON_LENIENT.parseToJsonElement(bytes.decodeToString())
            } catch (_: kotlinx.serialization.SerializationException) {
                return null
            }
        return parsed as? JsonObject
    }

    private fun JsonObject.stringClaim(name: String): String? =
        (this[name] as? JsonPrimitive)
            ?.takeIf { it.isString }
            ?.contentOrNull
            ?.takeIf { it.isNotBlank() }

    private fun JsonObject.stringArrayClaim(name: String): List<String>? =
        (this[name] as? JsonArray)
            ?.mapNotNull { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.contentOrNull }
            ?.filter { it.isNotBlank() }

    private fun JsonObject.vcIssuer(): String? {
        val issuerElement = this["issuer"]
        if (issuerElement is JsonPrimitive && issuerElement.isString) {
            return issuerElement.contentOrNull?.takeIf { it.isNotBlank() }
        }
        if (issuerElement is JsonObject) {
            issuerElement.stringClaim("id")?.let { return it }
        }
        val vc = this["vc"] as? JsonObject ?: return null
        val vcIssuer = vc["issuer"]
        if (vcIssuer is JsonPrimitive && vcIssuer.isString) {
            return vcIssuer.contentOrNull?.takeIf { it.isNotBlank() }
        }
        if (vcIssuer is JsonObject) {
            return vcIssuer.stringClaim("id")
        }
        return null
    }

    private fun String.isHttpUrl(): Boolean = startsWith("https://") || startsWith("http://")

    private fun String.extractDid(): String? {
        val value = substringAfter("decentralized_identifier:", this)
        if (!value.startsWith("did:")) return null
        val fragmentIndex = value.indexOf('#')
        val queryIndex = value.indexOf('?')
        val end =
            listOf(fragmentIndex, queryIndex)
                .filter { it >= 0 }
                .minOrNull()
                ?: value.length
        return value.substring(0, end)
    }

    /**
     * One projection per document of an mso_mdoc presentation.
     *
     * The presentation wire form is base64url(CBOR(DeviceResponse)) per ISO 18013-7 §B.3. Holder binding
     * has already been verified by the time this runs, so the CBOR decode is a pure structural read.
     * Each `IssuerSignedItem` value is converted from the item's original CBOR bytes, because the
     * decoded Kotlin value no longer knows its tags.
     */
    private fun mdocClaimProjections(presentation: String): IdkResult<List<CredentialClaimProjection>, IdkError> {
        val deviceResponseBytes =
            try {
                presentation.decodeFromBase64Url()
            } catch (expected: IllegalArgumentException) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "The mso_mdoc presentation is not base64url: ${expected.message}", throwable = expected))
            }
        val deviceResponse = deviceResponseCborCodec.decode(deviceResponseBytes).getOrElse { return Err(it) }.value
        val documents = deviceResponse.documents
        if (documents.isNullOrEmpty()) {
            return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "The mso_mdoc DeviceResponse contains no documents"))
        }
        val projections = mutableListOf<CredentialClaimProjection>()
        for (document in documents) {
            val elements = mutableListOf<MdocElement>()
            for (nameSpace in document.issuerSigned.getNameSpaces().orEmpty()) {
                for (item in document.issuerSigned.getNamespace(nameSpace.toString()).orEmpty()) {
                    val value = mdocElementValue(item.value.taggedItem.value, cborParser).getOrElse { return Err(it) }
                    elements += MdocElement(nameSpace.toString(), item.data().elementIdentifier.toString(), value)
                }
            }
            projections += mdocDocumentProjection(document.docType.toString(), elements)
        }
        return Ok(projections)
    }

    private companion object {
        /**
         * Prefix `evaluateCredentialStatus` uses for a present-but-unresolvable status reference; it is
         * the only signal separating that rejection from a required-but-absent one.
         */
        const val UNRESOLVABLE_STATUS_REASON_PREFIX = "status could not be resolved"

        /** Query formats whose credential type constraint is enforced through [CredentialTypeMatcher]. */
        val TYPE_CHECKED_FORMATS: Set<String> =
            setOf(CredentialFormat.SD_JWT_VC.value, CredentialFormat.JWT_VC_JSON.value, CredentialFormat.LDP_VC.value)

        const val MDOC_MIN_ENCODED_LENGTH = 20
        const val VCDM_MAX_RECURSION_DEPTH = 4
        const val VCDM_MAX_RECURSION_NODES = 32
        const val VCDM_MAX_DECODED_BYTES = 1024L * 1024L
        const val VCDM2_ENVELOPED_VC_TYPE = "EnvelopedVerifiableCredential"
        const val VCDM2_ENVELOPED_VP_TYPE = "EnvelopedVerifiablePresentation"
        const val VCDM2_VC_DATA_URI_PREFIX = "data:application/vc+jwt,"
        const val VCDM2_VP_DATA_URI_PREFIX = "data:application/vp+jwt,"
        const val LDP_VC_FORMAT = "ldp_vc"

        /** [CredentialIssuerRef.method] of an issuer admitted as an OpenID Federation entity. */
        const val FEDERATION_ISSUER_METHOD = "openid_federation"
        val VCDM2_ENVELOPED_TYPES = setOf(VCDM2_ENVELOPED_VC_TYPE, VCDM2_ENVELOPED_VP_TYPE)
        val JSON_LENIENT =
            Json {
                ignoreUnknownKeys = true
                isLenient = true
            }
    }
}

/**
 * X.509 roots of the credential-issuer authentications the verifier's persisted trust policy
 * resolved for this session. An mdoc revocation artifact is signed by its issuer, so these are the
 * roots that may verify it. Holder authentications and non-X.509 issuer evidence never contribute;
 * null when the session resolved no X.509 issuer evidence, so the status verifier keeps its own roots.
 */
internal fun mdocStatusTrustAnchors(
    trustedAuthentications: List<TrustedAuthenticationResolution>,
    documentType: String? = null,
): List<String>? {
    val issuerSources = trustedAuthentications.filter {
        it.purpose == TrustedAuthenticationPurpose.CREDENTIAL_ISSUER && it.identifier is ExternalIdentifierX5cOpts
    }
    if (issuerSources.isEmpty()) return null
    // An explicitly constrained source with no match yields an empty trust set, not null:
    // null would allow the status verifier to fall back to unrelated configured roots.
    return issuerSources
        .filter { it.documentTypes == null || (documentType != null && documentType in it.documentTypes!!) }
        .mapNotNull { it.identifier as? ExternalIdentifierX5cOpts }
        .flatMap { it.identifier }
        .distinct()
}
