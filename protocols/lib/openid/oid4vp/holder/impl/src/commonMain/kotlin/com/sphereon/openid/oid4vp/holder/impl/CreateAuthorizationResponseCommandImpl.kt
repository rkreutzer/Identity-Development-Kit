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

package com.sphereon.openid.oid4vp.holder.impl

import com.sphereon.ktor.http.client.provider.withCounterpartyEgress
import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.decodeFromBase64Url
import com.sphereon.core.api.encodeToBase64Url
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.service.TypedServiceCommandAdapter
import com.sphereon.core.compat.Uuid
import com.sphereon.crypto.core.KeyInfo
import com.sphereon.crypto.core.KeyVisibility
import com.sphereon.crypto.core.jose.Jwk
import com.sphereon.crypto.core.jose.tryGenerateJwkThumbprint
import com.sphereon.crypto.dataintegrity.command.AddProofServiceCommand
import com.sphereon.crypto.jose.jws.StrictCompactJws
import com.sphereon.di.session.SessionScope
import com.sphereon.mdoc.data.device.DataElementIdentifier
import com.sphereon.mdoc.data.device.DeviceResponseCborCodec
import com.sphereon.mdoc.data.device.Document
import com.sphereon.mdoc.data.device.IssuerSigned
import com.sphereon.mdoc.data.device.IssuerSignedCborCodec
import com.sphereon.mdoc.data.device.NameSpace
import com.sphereon.mdoc.data.mso.MobileSecurityObjectCborCodec
import com.sphereon.mdoc.oid4vp.MdocOid4vpService
import com.sphereon.mdoc.oid4vp.PreparedMdocDeviceResponseSigning
import com.sphereon.mdoc.oid4vp.MdocDeviceResponseSignature
import com.sphereon.mdoc.oid4vp.Oid4vpDeviceAuthenticationContext
import com.sphereon.mdoc.oid4vp.Oid4VPConstraintField
import com.sphereon.mdoc.oid4vp.Oid4VPConstraints
import com.sphereon.mdoc.oid4vp.Oid4VPFormat
import com.sphereon.mdoc.oid4vp.Oid4VPInputDescriptor
import com.sphereon.mdoc.oid4vp.Oid4VPPresentationDefinition
import com.sphereon.mdoc.oid4vp.Oid4VPPresentationSubmission
import com.sphereon.mdoc.oid4vp.Oid4VPSupportedAlgorithm
import com.sphereon.oauth2.common.model.AuthorizationResponse
import com.sphereon.oauth2.common.jarm.JarmConfig
import com.sphereon.openid.oid4vc.common.PresentationFormat
import com.sphereon.openid.oid4vc.common.vcdm.VcdmClassifier
import com.sphereon.openid.oid4vc.common.vcdm.VcdmDocumentKind
import com.sphereon.openid.oid4vc.common.vcdm.VcdmProfiles
import com.sphereon.openid.oid4vc.common.vcdm.VcdmVersion
import com.sphereon.openid.oid4vp.common.CredentialFormat
import com.sphereon.openid.oid4vp.common.ResponseMode
import com.sphereon.openid.oid4vp.common.VpToken
import com.sphereon.openid.oid4vp.common.buildOid4vpAuthorizationResponse
import com.sphereon.openid.oid4vp.common.responseUri
import com.sphereon.openid.oid4vp.common.selectEncryptedResponseJwk
import com.sphereon.openid.oid4vp.holder.CreateAuthorizationResponseArgs
import com.sphereon.openid.oid4vp.holder.CreateAuthorizationResponseCommand
import com.sphereon.openid.oid4vp.holder.CreateAuthorizationResponseCommandService
import com.sphereon.openid.oid4vp.holder.HolderJwtVpSigningIdentifier
import com.sphereon.openid.oid4vp.holder.HolderJwtVpSigningProvider
import com.sphereon.openid.oid4vp.holder.HolderJwtVpSigningRequest
import com.sphereon.openid.oid4vp.holder.HolderJwtVpSigningResult
import com.sphereon.openid.oid4vp.holder.HolderPreparedJwtVp
import com.sphereon.openid.oid4vp.holder.HolderPreparedJwtVpResponse
import com.sphereon.openid.oid4vp.holder.PreparedMdocCredentialSigning
import com.sphereon.openid.oid4vp.holder.PreparedOid4vpJweRecipientBinding
import com.sphereon.openid.oid4vp.holder.MdocCredentialSigningSignature
import com.sphereon.openid.oid4vp.holder.PreparedPresentation
import com.sphereon.openid.oid4vp.holder.ResolvedOid4vpRequest
import com.sphereon.openid.oid4vp.holder.SelectedCredential
import com.sphereon.openid.oid4vp.holder.credentialDisclosurePathOptions
import com.sphereon.sdjwt.SdJwtCodec
import com.sphereon.sdjwt.SdJwtPresentation
import dev.zacsweers.metro.ExposeImplBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import kotlin.time.Clock
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject

private sealed interface MdocPresentationResolution {
    data class WireValue(val value: String) : MdocPresentationResolution
    data class PreparedSigning(val value: PreparedMdocCredentialSigning) : MdocPresentationResolution
}

/**
 * Implementation of CreateAuthorizationResponseCommand for OpenID4VP.
 *
 * Creates an authorization response by:
 * - Matching selected credentials against DCQL query
 * - Building VP tokens in the appropriate format (jwt_vc, ldp_vc, mso_mdoc, etc.)
 * - Applying holder binding if required
 * - Constructing the response parameters
 *
 * Reference: OpenID4VP 1.0 Section 6 - Authorization Response
 *
 * Response format (OpenID4VP 1.0 Final):
 * - vp_token: Self-descriptive credential(s)
 * - state: State from original request (if present)
 * - Note: presentation_submission is NOT used in OID4VP 1.0 Final (DCQL responses are self-descriptive)
 *
 * VP Token formats:
 * - JWT VP: Verifiable Presentation in JWT format
 * - SD-JWT: Selective Disclosure JWT
 * - mDoc/mDL: ISO 18013-5 mobile documents
 * - LDP VP: JSON-LD Verifiable Presentation
 */
@Inject
@SingleIn(SessionScope::class)
@ExposeImplBinding
class CreateAuthorizationResponseCommandImpl(
    execution: SessionExecution,
    /** Explicit holder-side JWT VP signing seam; private keys never resolve in this command. */
    private val holderJwtVpSigningProvider: HolderJwtVpSigningProvider,
    /** Cross-platform Data Integrity proof service backed by the configured KMS/provider graph. */
    private val addProofServiceCommand: AddProofServiceCommand,
    /**
     * mdoc OID4VP presentation service (ISO 18013-5 / 18013-7). Builds the ISO
     * `DeviceResponse` with a `DeviceAuth` COSE_Sign1 over the OID4VP §B.2.6
     * `OpenID4VPHandover` SessionTranscript for `mso_mdoc` credentials.
     */
    private val mdocOid4vpService: MdocOid4vpService,
    /** Decodes the stored `mso_mdoc` credential (base64url(CBOR(IssuerSigned))). */
    private val issuerSignedCborCodec: IssuerSignedCborCodec,
    /** Encodes the produced ISO `DeviceResponse` to CBOR for the vp_token entry. */
    private val deviceResponseCborCodec: DeviceResponseCborCodec,
    /** Reads the issued MSO (docType + device key) out of the stored `IssuerSigned`. */
    private val mobileSecurityObjectCborCodec: MobileSecurityObjectCborCodec,
) : TypedServiceCommandAdapter<CreateAuthorizationResponseArgs, AuthorizationResponse, IdkError>(
        commandId = CreateAuthorizationResponseCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<CreateAuthorizationResponseArgs>(),
        outputTypeToken = typeToken<AuthorizationResponse>(),
    ),
    CreateAuthorizationResponseCommand,
    CreateAuthorizationResponseCommandService {
    override val commandId: String get() = CreateAuthorizationResponseCommand.COMMAND_ID

    override suspend fun supports(args: Any): Boolean = args is CreateAuthorizationResponseArgs

    override suspend fun createAuthorizationResponse(
        request: ResolvedOid4vpRequest,
        selectedCredentials: List<SelectedCredential>,
        preparedPresentations: List<PreparedPresentation>,
    ): IdkResult<AuthorizationResponse, IdkError> = execute(CreateAuthorizationResponseArgs(request, selectedCredentials, preparedPresentations))

    override suspend fun createAuthorizationResponseWithPreparedMdocDeviceAuthenticationSignatures(
        request: ResolvedOid4vpRequest,
        selectedCredentials: List<SelectedCredential>,
        preparedPresentations: List<PreparedPresentation>,
        preparedMdocSignings: List<PreparedMdocCredentialSigning>,
        signatures: List<MdocCredentialSigningSignature>,
    ): IdkResult<AuthorizationResponse, IdkError> = execute(
        CreateAuthorizationResponseArgs(
            request = request,
            selectedCredentials = selectedCredentials,
            preparedPresentations = preparedPresentations,
            preparedMdocSignings = preparedMdocSignings,
            preparedMdocSignatures = signatures,
        ),
    )

    override suspend fun createAuthorizationResponseWithPreparedSignatures(
        request: ResolvedOid4vpRequest,
        selectedCredentials: List<SelectedCredential>,
        preparedPresentations: List<PreparedPresentation>,
        preparedJwtVp: HolderPreparedJwtVpResponse?,
        jwtSignatures: List<HolderJwtVpSigningResult>,
        preparedMdocSignings: List<PreparedMdocCredentialSigning>,
        mdocSignatures: List<MdocCredentialSigningSignature>,
    ): IdkResult<AuthorizationResponse, IdkError> = execute(
        CreateAuthorizationResponseArgs(
            request = request,
            selectedCredentials = selectedCredentials,
            preparedPresentations = preparedPresentations,
            preparedJwtVp = preparedJwtVp,
            preparedJwtVpSignatures = jwtSignatures,
            preparedMdocSignings = preparedMdocSignings,
            preparedMdocSignatures = mdocSignatures,
        ),
    )

    override suspend fun prepareMdocDeviceAuthenticationSignatures(
        request: ResolvedOid4vpRequest,
        selectedCredentials: List<SelectedCredential>,
    ): IdkResult<List<PreparedMdocCredentialSigning>, IdkError> = withCounterpartyEgress {
        if (request.authorizationError != null) {
            return@withCounterpartyEgress Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "An invalid authorization request cannot prepare credential signatures"))
        }
        validateSelectedCredentialFormats(request, selectedCredentials).getOrElse { return@withCounterpartyEgress Err(it) }
        if (selectedCredentials.map { it.credentialId }.toSet().size != selectedCredentials.size) {
            return@withCounterpartyEgress Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Selected credential IDs must be unique"))
        }
        val mdocCredentials = selectedCredentials.filter { it.credentialFormat.isMdoc }
        if (mdocCredentials.isEmpty()) {
            return@withCounterpartyEgress Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "At least one selected mdoc credential is required"))
        }
        val result = mutableListOf<PreparedMdocCredentialSigning>()
        for (credential in mdocCredentials) {
            val prepared = resolveMdocPresentation(request, credential, prepareOnly = true).getOrElse { return@withCounterpartyEgress Err(it) }
            val record = (prepared as? MdocPresentationResolution.PreparedSigning)?.value
                ?: return@withCounterpartyEgress Err(IdkError.UNKNOWN_ERROR(message = "mdoc signing preparation did not return a signing snapshot"))
            result += record
        }
        Ok(result)
    }

    // Everything a holder command fetches runs under the counterparty egress rule, also in the components shared with servers.
    override suspend fun doExecute(
        args: CreateAuthorizationResponseArgs,
        applyDuring: (CreateAuthorizationResponseArgs) -> CreateAuthorizationResponseArgs,
    ): IdkResult<AuthorizationResponse, IdkError> = withCounterpartyEgress { executeUnderEgressRule(args, applyDuring) }

    private suspend fun executeUnderEgressRule(
        args: CreateAuthorizationResponseArgs,
        applyDuring: (CreateAuthorizationResponseArgs) -> CreateAuthorizationResponseArgs,
    ): IdkResult<AuthorizationResponse, IdkError> {
        val processedArgs = applyDuring(args)
        if (processedArgs.request.authorizationError != null) {
            return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "An invalid authorization request cannot receive a credential presentation"))
        }
        val request = processedArgs.request
        val selectedCredentials = processedArgs.selectedCredentials
        val preparedPresentations = processedArgs.preparedPresentations

        log.debug("Creating authorization response for ${selectedCredentials.size} selected credential(s)")

        // Validate that credentials were provided
        if (selectedCredentials.isEmpty()) {
            log.error("No credentials selected for authorization response")
            return Err(
                IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message = "At least one credential must be selected",
                ),
            )
        }

        // ISO/IEC 18013-7 deployments using mdoc-openid4vp carry a Presentation Definition.
        // Keep the protocol in this holder command: UI and interaction orchestration still use
        // the normalized credential requirements, while the wire response retains the profile's
        // vp_token + presentation_submission shape.
        val presentationDefinition = parsePresentationDefinition(request)
        if (presentationDefinition != null) {
            if (processedArgs.preparedJwtVp != null || processedArgs.preparedJwtVpSignatures.isNotEmpty() ||
                processedArgs.preparedMdocSignings.isNotEmpty() || processedArgs.preparedMdocSignatures.isNotEmpty()) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Prepared holder signatures require a DCQL response"))
            }
            if (selectedCredentials.size != 1 || presentationDefinition.input_descriptors.size != 1) {
                return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message =
                            "The mdoc Presentation Definition response currently requires exactly one " +
                                "input descriptor and one selected credential",
                    ),
                )
            }
            val presentationElement = resolvePresentation(request, selectedCredentials.single()).getOrElse { return Err(it) }
            val presentation = presentationElement.compactStringOrNull()
                ?: return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message = "The mdoc Presentation Definition response requires a compact string presentation",
                    ),
                )
            val submission = Oid4VPPresentationSubmission.fromPresentationDefinition(presentationDefinition)
            return Ok(
                AuthorizationResponse(
                    code = "",
                    state = request.request.state,
                    additionalParameters =
                        mapOf(
                            "vp_token" to JsonPrimitive(presentation),
                            "presentation_submission" to
                                responseJson.encodeToJsonElement(Oid4VPPresentationSubmission.serializer(), submission),
                        ),
                ),
            )
        }

        // Build VP token from selected credentials. For SD-JWT credentials that carry a holder
        // key, the holder produces a Key Binding JWT (RFC 9901 §4.3) binding the presentation to
        // the verifier (audience = client_id) and the request nonce; other formats pass through.
        val vpToken =
            buildVpToken(
                request,
                selectedCredentials,
                preparedPresentations,
                processedArgs.preparedJwtVp,
                processedArgs.preparedJwtVpSignatures,
                processedArgs.preparedMdocSignings,
                processedArgs.preparedMdocSignatures,
            ).getOrElse { error ->
                return Err(error)
            }

        log.info("Created VP token with ${selectedCredentials.size} presentation(s)")

        // Build authorization response using type-safe builder
        // OpenID4VP 1.0 Final: vp_token is self-descriptive, no presentation_submission needed
        val response =
            buildOid4vpAuthorizationResponse {
                vpToken(vpToken)
                request.request.state?.let { state(it) }
            }

        log.debug("Authorization response created successfully")
        return Ok(response)
    }

    /**
     * Build VP token from selected credentials.
     *
     * OpenID4VP 1.0 Final §8.1 (DCQL Format):
     * - vp_token is a JSON object where keys are credential query IDs
     * - Every value is an array of one or more Presentations
     *
     * Example:
     * ```json
     * {
     *   "driver_license_query": ["eyJhbGc..."],
     *   "employment_query": ["eyJhbGc...", "eyJhbGc..."]
     * }
     * ```
     *
     * For an SD-JWT Credential Query whose `require_cryptographic_holder_binding` is true (the
     * default), the holder appends a freshly signed Key Binding JWT. When the query explicitly
     * sets the flag to false, the holder returns the selectively disclosed SD-JWT without KB-JWT.
     *
     * Note: SelectedCredential.credentialQueryId maps the presentation to its DCQL credential
     * query. Multiple credentials can satisfy the same query.
     */
    private suspend fun buildVpToken(
        request: ResolvedOid4vpRequest,
        credentials: List<SelectedCredential>,
        preparedPresentations: List<PreparedPresentation>,
        preparedJwtVp: HolderPreparedJwtVpResponse?,
        signatures: List<HolderJwtVpSigningResult>,
        preparedMdocSignings: List<PreparedMdocCredentialSigning>,
        mdocSignatures: List<MdocCredentialSigningSignature>,
    ): IdkResult<VpToken, IdkError> {
        validateSelectedCredentialFormats(request, credentials).getOrElse { return Err(it) }
        validatePreparedPresentations(request, credentials, preparedPresentations).getOrElse { return Err(it) }
        val preparedJwtById = validatePreparedJwtPresentations(request, credentials, preparedJwtVp, signatures)
            .getOrElse { return Err(it) }
        val preparedMdocById = validatePreparedMdocSignings(credentials, preparedMdocSignings, mdocSignatures)
            .getOrElse { return Err(it) }
        val withPresentations = mutableListOf<Pair<String, JsonElement>>()
        val preparedByCredentialId = preparedPresentations.flatMap { prepared ->
            prepared.credentialIds.map { credentialId -> credentialId to prepared }
        }.toMap()
        val emittedPrepared = mutableSetOf<PreparedPresentation>()
        for (credential in credentials) {
            preparedByCredentialId[credential.credentialId]?.let { prepared ->
                if (emittedPrepared.add(prepared)) {
                    prepared.credentialQueryIds.forEach { queryId ->
                        withPresentations += queryId to prepared.presentation
                    }
                }
                return@let
            } ?: run {
                val presentation =
                    preparedJwtById[credential.credentialId]
                        ?: resolvePresentation(
                            request,
                            credential,
                            preparedMdocById[credential.credentialId]?.first,
                            preparedMdocById[credential.credentialId]?.second,
                        ).getOrElse { return Err(it) }
                withPresentations += credential.credentialQueryId to presentation
            }
        }

        val grouped =
            withPresentations
                .groupBy({ it.first }, { it.second })

        return Ok(VpToken(grouped))
    }

    private fun validatePreparedMdocSignings(
        credentials: List<SelectedCredential>,
        prepared: List<PreparedMdocCredentialSigning>,
        signatures: List<MdocCredentialSigningSignature>,
    ): IdkResult<Map<String, Pair<PreparedMdocCredentialSigning, MdocCredentialSigningSignature>>, IdkError> {
        val selected = credentials.filter { it.credentialFormat.isMdoc }
        if (prepared.isEmpty() && signatures.isEmpty()) return Ok(emptyMap())
        if (prepared.size != selected.size || signatures.size != selected.size) {
            return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Prepared mdoc signing must cover every selected mdoc credential exactly once"))
        }
        val preparedById = prepared.associateBy { it.credentialId }
        val signaturesById = signatures.associateBy { it.credentialId }
        val selectedById = selected.associateBy { it.credentialId }
        if (preparedById.size != prepared.size || signaturesById.size != signatures.size ||
            selectedById.size != selected.size || preparedById.keys != selectedById.keys || signaturesById.keys != selectedById.keys) {
            return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Prepared mdoc signing records do not match selected credentials"))
        }
        val result = mutableMapOf<String, Pair<PreparedMdocCredentialSigning, MdocCredentialSigningSignature>>()
        for ((credentialId, credential) in selectedById) {
            val record = preparedById.getValue(credentialId)
            if (record.credentialQueryId != credential.credentialQueryId ||
                record.keyReference != credential.holderKeyRef ||
                record.docType != record.signing.docType ||
                record.signing.keyReference != record.keyReference) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Prepared mdoc signing is bound to different selected credential inputs"))
            }
            result[credentialId] = record to signaturesById.getValue(credentialId)
        }
        return Ok(result)
    }

    /** Revalidates ownership, query mapping and the exact canonical payload without signing again. */
    private fun validatePreparedJwtPresentations(
        request: ResolvedOid4vpRequest,
        credentials: List<SelectedCredential>,
        prepared: HolderPreparedJwtVpResponse?,
        signatures: List<HolderJwtVpSigningResult>,
    ): IdkResult<Map<String, JsonElement>, IdkError> {
        if (prepared == null) {
            return if (signatures.isEmpty()) Ok(emptyMap())
            else Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "JWT VP signatures require their prepared inputs"))
        }
        val selected = credentials.filter {
            it.credentialFormat == CredentialFormat.JWT_VC_JSON || it.credentialFormat == CredentialFormat.JWT_VC_JSON_LD
        }
        if (prepared.state != request.request.state || selected.isEmpty() ||
            prepared.presentations.map { it.credentialQueryId to it.credentialId } !=
            selected.map { it.credentialQueryId to it.credentialId } || signatures.size != selected.size) {
            return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Prepared JWT VP selection changed"))
        }
        val result = mutableMapOf<String, JsonElement>()
        for ((index, credential) in selected.withIndex()) {
            val saved = prepared.presentations[index].signingRequest
            val fresh = prepareVcdmJwtPresentation(request, credential, credential.credentialFormat).getOrElse { return Err(it) }
            val issuedAt = saved.payload["iat"]
                ?: return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Prepared JWT VP issued-at is missing"))
            if (fresh.copy(payload = JsonObject(fresh.payload + ("iat" to issuedAt))) != saved) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Prepared JWT VP request or credential changed"))
            }
            result[credential.credentialId] = JsonPrimitive(
                validateSignedJwtVp(saved, signatures[index], requireExactPayload = true).getOrElse { return Err(it) },
            )
        }
        return Ok(result)
    }

    private fun validateSelectedCredentialFormats(
        request: ResolvedOid4vpRequest,
        credentials: List<SelectedCredential>,
    ): IdkResult<Unit, IdkError> {
        val dcqlQuery = request.dcqlQuery ?: return Ok(Unit)
        credentials.forEach { credential ->
            val query = dcqlQuery.credentials.find { it.id == credential.credentialQueryId }
                ?: return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message = "Selected credential references unknown DCQL Credential Query '${credential.credentialQueryId}'",
                    ),
                )
            val requestedFormat = CredentialFormat.fromValueLenient(query.format)
                ?: return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message = "DCQL Credential Query '${query.id}' uses unsupported credential format '${query.format}'",
                    ),
                )
            if (requestedFormat != credential.credentialFormat) {
                return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message = "Selected credential '${credential.credentialId}' declares ${credential.credentialFormat.value}, " +
                            "but DCQL Credential Query '${query.id}' requires ${requestedFormat.value}",
                    ),
                )
            }
        }
        return Ok(Unit)
    }

    private fun validatePreparedPresentations(
        request: ResolvedOid4vpRequest,
        credentials: List<SelectedCredential>,
        preparedPresentations: List<PreparedPresentation>,
    ): IdkResult<Unit, IdkError> {
        val dcqlQuery = request.dcqlQuery
        val selectedById = credentials.associateBy { it.credentialId }
        if (selectedById.size != credentials.size) {
            return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Selected credential IDs must be unique"))
        }
        val preparedCredentialIds = mutableSetOf<String>()
        preparedPresentations.forEach { prepared ->
            if (prepared.credentialIds.isEmpty() || prepared.credentialIds.size != prepared.credentialIds.toSet().size) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Prepared presentation must identify one or more unique selected credential IDs"))
            }
            if (prepared.credentialIds.any { it in preparedCredentialIds }) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "A selected credential cannot belong to multiple prepared presentations"))
            }
            preparedCredentialIds.addAll(prepared.credentialIds)
            val selected = prepared.credentialIds.map { credentialId ->
                selectedById[credentialId]
                    ?: return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Prepared presentation references unselected credential '$credentialId'"))
            }
            val selectedQueryIds = selected.map { it.credentialQueryId }.toSet()
            if (prepared.credentialQueryIds.isEmpty() || prepared.credentialQueryIds.size != prepared.credentialQueryIds.toSet().size ||
                prepared.credentialQueryIds.toSet() != selectedQueryIds
            ) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Prepared presentation query IDs must exactly match its selected credentials"))
            }
            when (prepared.presentationFormat) {
                PresentationFormat.LDP_VP -> if (selected.any { it.credentialFormat != CredentialFormat.LDP_VC }) {
                    return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Prepared ldp_vp may contain only ldp_vc credentials"))
                }
                PresentationFormat.JWT_VP_JSON -> {
                    return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "JWT VPs must be produced separately for each selected JWT credential"))
                }
            }
            if (dcqlQuery != null && prepared.credentialQueryIds.any { queryId ->
                    dcqlQuery.credentials.none { it.id == queryId }
                }) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Prepared presentation references an unknown DCQL Credential Query"))
            }
        }
        return Ok(Unit)
    }

    /**
     * Resolve the wire presentation for a selected credential.
     *
     * - `mso_mdoc`: the stored credential is the issued `IssuerSigned` (base64url(CBOR)). The
     *   holder decodes it, builds an ISO `DeviceResponse` whose `DeviceAuth` COSE_Sign1 is signed
     *   over the OID4VP §B.2.6 `OpenID4VPHandover` SessionTranscript (bound to `client_id`,
     *   `nonce`, `response_uri`) using the holder's device key, and submits base64url(CBOR) of
     *   that `DeviceResponse`. See [resolveMdocPresentation].
     * - `dc+sd-jwt` / `vc+sd-jwt`: the holder validates a presentation prepared by the caller's
     *   holder-signing surface. Wallet callers prepare it through WSCA and WSCD; this protocol
     *   command never resolves or uses holder keys itself.
     * - everything else is submitted as stored.
     */
    private suspend fun resolvePresentation(
        request: ResolvedOid4vpRequest,
        credential: SelectedCredential,
        preparedMdocSigning: PreparedMdocCredentialSigning? = null,
        mdocSignature: MdocCredentialSigningSignature? = null,
    ): IdkResult<JsonElement, IdkError> {
        val format = credential.credentialFormat
        val holderKeyRef = credential.holderKeyRef
        val credentialQuery = request.dcqlQuery?.credentials?.find { it.id == credential.credentialQueryId }

        if (request.dcqlQuery != null && credentialQuery == null) {
            return Err(
                IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message = "Selected credential references unknown DCQL Credential Query '${credential.credentialQueryId}'",
                ),
            )
        }

        if (credentialQuery != null) {
            val requestedFormat = CredentialFormat.fromValueLenient(credentialQuery.format)
                ?: return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message = "DCQL Credential Query '${credentialQuery.id}' uses unsupported credential format '${credentialQuery.format}'",
                    ),
                )
            if (requestedFormat != format) {
                return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message = "Selected credential '${credential.credentialId}' declares ${format.value}, " +
                            "but DCQL Credential Query '${credentialQuery.id}' requires ${requestedFormat.value}",
                    ),
                )
            }
        }

        if (format.isMdoc) {
            val presentation = resolveMdocPresentation(request, credential, preparedMdocSigning, mdocSignature).getOrElse { return Err(it) }
            return when (presentation) {
                is MdocPresentationResolution.WireValue -> Ok(JsonPrimitive(presentation.value))
                is MdocPresentationResolution.PreparedSigning -> Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "mdoc signing preparation cannot be used as a wire presentation"))
            }
        }

        if (format == CredentialFormat.JWT_VC_JSON || format == CredentialFormat.JWT_VC_JSON_LD) {
            val presentation = resolveVcdmJwtPresentation(request, credential, format).getOrElse { return Err(it) }
            return Ok(JsonPrimitive(presentation))
        }

        if (format == CredentialFormat.LDP_VC) {
            return resolveVcdmDataIntegrityPresentation(request, credential)
        }

        if (!format.isSdJwt) {
            return Ok(credential.presentation)
        }

        val compactPresentation = credential.presentation.compactStringOrNull()
            ?: return Err(
                IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message = "Selected ${format.value} credential '${credential.credentialId}' must be a JSON string",
                ),
            )

        // A null Credential Query denotes the non-DCQL/presentation-definition path. Preserve its
        // established behavior because it has no DCQL holder-binding flag to interpret.
        if (credentialQuery == null && holderKeyRef.isNullOrBlank()) {
            return Ok(credential.presentation)
        }

        val requireHolderBinding = credentialQuery?.require_cryptographic_holder_binding ?: true
        val referencedByTransactionData =
            request.transactionData.orEmpty().any {
                credential.credentialQueryId in it.transactionData.credentialIds
            }
        if (referencedByTransactionData && !requireHolderBinding) {
            return Err(
                IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message =
                        "Transaction data references Credential Query '${credential.credentialQueryId}', " +
                            "but require_cryptographic_holder_binding is false",
                ),
            )
        }

        if (credential.sdJwtKeyBindingApplied && !holderKeyRef.isNullOrBlank()) {
            return Err(
                IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message =
                        "Selected SD-JWT credential '${credential.credentialId}' cannot carry both " +
                            "an opaque holder key reference and an already-applied Key Binding JWT",
                ),
            )
        }

        val appliedKeyBindingJwt =
            if (credential.sdJwtKeyBindingApplied) {
                SdJwtCodec
                    .parse(compactPresentation)
                    .getOrElse { return Err(it) }
                    .keyBindingJwt
                    ?: return Err(
                        IdkError.ILLEGAL_ARGUMENT_ERROR(
                            message =
                                "Selected SD-JWT credential '${credential.credentialId}' is marked as holder-bound " +
                                    "but its presentation contains no Key Binding JWT",
                        ),
                    )
            } else {
                null
            }

        if (requireHolderBinding && !holderKeyRef.isNullOrBlank()) {
            return Err(
                IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message =
                        "Selected SD-JWT credential '${credential.credentialId}' still carries a holder key reference. " +
                            "Holder signing must be completed through WSCA and WSCD before authorization-response assembly",
                ),
            )
        }

        if (requireHolderBinding && appliedKeyBindingJwt == null) {
            return Err(
                IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message =
                        "Credential Query '${credential.credentialQueryId}' requires cryptographic holder binding, " +
                            "but the selected SD-JWT presentation has not been prepared by the holder signing surface",
                ),
            )
        }

        val nonce = if (requireHolderBinding) request.request.nonce else null
        if (requireHolderBinding && nonce == null) {
            return Err(
                IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message =
                        "Cannot create SD-JWT Key Binding JWT for query '${credential.credentialQueryId}': " +
                            "authorization request has no nonce",
                ),
            )
        }
        val audience = if (requireHolderBinding) request.verifierInfo.clientId else null

        if (appliedKeyBindingJwt != null) {
            if (requireHolderBinding && appliedKeyBindingJwt.audience != audience) {
                return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message =
                            "Applied SD-JWT Key Binding JWT audience '${appliedKeyBindingJwt.audience}' " +
                                "does not match verifier '$audience'",
                    ),
                )
            }
            if (requireHolderBinding && appliedKeyBindingJwt.nonce != nonce) {
                return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message =
                            "Applied SD-JWT Key Binding JWT nonce does not match the authorization request nonce",
                    ),
                )
            }
            return Ok(JsonPrimitive(compactPresentation))
        }

        // With holder binding disabled, disclosure selection is pure standards processing. No key
        // operation is needed or permitted here.
        return runCatching {
            val paths =
                credentialQuery?.let {
                    SdJwtPresentation.firstSatisfiableDisclosurePaths(
                        compact = compactPresentation,
                        options = request.credentialDisclosurePathOptions(credential.credentialQueryId),
                    )
                }
            Ok(JsonPrimitive(SdJwtPresentation.select(compact = compactPresentation, disclosurePaths = paths).presentationWithoutKeyBinding))
        }.getOrElse {
            Err(
                IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message = "Failed to select SD-JWT disclosures for query '${credential.credentialQueryId}': ${it.message}",
                ),
            )
        }
    }

    /**
     * Create one holder-bound VCDM Verifiable Presentation for one selected VC.
     *
     * The selected credential remains an independently issuer-secured VC. This method signs a
     * separate VP for that one VC, even when another selected credential uses the same holder key.
     * VCDM 1.1 uses the JWT `vp` wrapper; VCDM 2.0 uses a JSON-LD VP at the JOSE payload root and
     * represents its VC child as an EnvelopedVerifiableCredential data URI object.
     */
    internal fun prepareJwtVpResponse(
        request: ResolvedOid4vpRequest,
        credentials: List<SelectedCredential>,
    ): IdkResult<HolderPreparedJwtVpResponse, IdkError> {
        if (request.authorizationError != null) {
            return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "An invalid authorization request cannot prepare credential signatures"))
        }
        if (credentials.isEmpty() || credentials.map { it.credentialId }.distinct().size != credentials.size ||
            parsePresentationDefinition(request) != null || credentials.any {
                it.credentialFormat != CredentialFormat.JWT_VC_JSON && it.credentialFormat != CredentialFormat.JWT_VC_JSON_LD
            }) return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "JWT VP preparation requires unique JWT credentials and a DCQL response"))
        validateSelectedCredentialFormats(request, credentials).getOrElse { return Err(it) }
        val presentations = credentials.map { credential ->
            val signing = prepareVcdmJwtPresentation(request, credential, credential.credentialFormat).getOrElse { return Err(it) }
            HolderPreparedJwtVp(credential.credentialQueryId, credential.credentialId, signing)
        }
        return Ok(HolderPreparedJwtVpResponse(request.request.state, presentations))
    }

    internal fun finalizeJwtVpResponse(
        prepared: HolderPreparedJwtVpResponse,
        signatures: List<HolderJwtVpSigningResult>,
    ): IdkResult<AuthorizationResponse, IdkError> {
        if (prepared.presentations.isEmpty() || signatures.size != prepared.presentations.size ||
            prepared.presentations.map { it.credentialId }.distinct().size != prepared.presentations.size) {
            return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "JWT VP finalization requires exactly one signature per prepared credential"))
        }
        val presentations = prepared.presentations.zip(signatures).map { (item, signature) ->
            val compact = validateSignedJwtVp(item.signingRequest, signature, requireExactPayload = true).getOrElse { return Err(it) }
            item.credentialQueryId to JsonPrimitive(compact)
        }
        return Ok(buildOid4vpAuthorizationResponse {
            vpToken(VpToken(presentations.groupBy({ it.first }, { it.second })))
            prepared.state?.let { state(it) }
        })
    }

    private suspend fun resolveVcdmJwtPresentation(
        request: ResolvedOid4vpRequest,
        credential: SelectedCredential,
        format: CredentialFormat,
    ): IdkResult<String, IdkError> {
        val prepared = prepareVcdmJwtPresentation(request, credential, format).getOrElse { return Err(it) }
        val signed = holderJwtVpSigningProvider.sign(prepared).getOrElse { return Err(it) }
        return validateSignedJwtVp(prepared, signed)
    }

    private fun prepareVcdmJwtPresentation(
        request: ResolvedOid4vpRequest,
        credential: SelectedCredential,
        format: CredentialFormat,
    ): IdkResult<HolderJwtVpSigningRequest, IdkError> {
        val compactCredential = credential.presentation.compactStringOrNull()
            ?: return Err(
                IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message = "Selected ${format.value} credential '${credential.credentialId}' must be a compact JWT string",
                ),
            )
        val classifiedCredential = VcdmClassifier.classifyCompactJws(compactCredential).getOrElse { return Err(it) }
        if (classifiedCredential.document.kind != VcdmDocumentKind.CREDENTIAL) {
            return Err(
                IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message = "Selected ${format.value} input '${credential.credentialId}' is not a VCDM credential",
                ),
            )
        }
        if (classifiedCredential.credentialFormat != format) {
            return Err(
                IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message =
                            "Selected credential '${credential.credentialId}' is ${classifiedCredential.credentialFormat?.value}, " +
                            "not the declared ${format.value} format",
                ),
            )
        }
        val profileValidation =
            if (classifiedCredential.document.version == VcdmVersion.V1_1) {
                VcdmProfiles.v1_1.validateCredential(classifiedCredential.document.json)
            } else {
                VcdmProfiles.v2_0.validateCredential(classifiedCredential.document.json)
            }
        if (!profileValidation.valid) {
            return Err(
                IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message =
                        "Selected credential '${credential.credentialId}' does not satisfy its VCDM profile: " +
                            profileValidation.errors.joinToString { it.message.defaultMessage },
                ),
            )
        }
        val holderKeyRef = credential.holderKeyRef?.takeIf { it.isNotBlank() }
        if (holderKeyRef == null) {
            return Err(
                IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message = "Cannot create VCDM Verifiable Presentation: holder key reference is missing",
                ),
            )
        }
        val holderId = credential.holderId?.takeIf { it.isNotBlank() }
        if (holderId == null) {
            return Err(
                IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message = "Cannot create VCDM Verifiable Presentation: holder identifier is missing",
                ),
            )
        }
        val holderSigningAlgorithm = credential.holderSigningAlgorithm
            ?: return Err(
                IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message = "Cannot create VCDM Verifiable Presentation: holder signing algorithm is missing",
                ),
            )
        val expectedJoseAlgorithm = holderSigningAlgorithm.jose
            ?.takeIf { it.type == com.sphereon.crypto.core.jose.AlgorithmType.SIGNATURE }
            ?.value
            ?: return Err(
                IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message = "Cannot create VCDM Verifiable Presentation: holder signing algorithm has no JOSE signature mapping",
                ),
            )
        // OID4VP 1.0 keys vp_formats_supported by Credential Format Identifier. The VP artifact
        // has its own PresentationFormat, but that must not replace the selected VC format as the
        // metadata lookup key.
        val verifierAlgorithms = request.clientMetadata
            ?.vpFormatsSupported
            ?.get(format.value)
            ?.algValuesSupported
        if (verifierAlgorithms.isNullOrEmpty()) {
            return Err(
                IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message = "Verifier metadata must advertise non-empty alg_values for ${format.value}",
                ),
            )
        }
        if (expectedJoseAlgorithm !in verifierAlgorithms) {
            return Err(
                IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message = "Holder signing algorithm '$expectedJoseAlgorithm' is not accepted for ${format.value}: $verifierAlgorithms",
                ),
            )
        }
        val nonce = request.request.nonce?.takeIf { it.isNotBlank() }
        if (nonce == null) {
            return Err(
                IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message = "Cannot create VCDM Verifiable Presentation: authorization request nonce is missing",
                ),
            )
        }
        val audience = request.verifierInfo.clientId.takeIf { it.isNotBlank() }
        if (audience == null) {
            return Err(
                IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message = "Cannot create VCDM Verifiable Presentation: verifier audience is missing",
                ),
            )
        }

        val vpPayload =
            when (format) {
                CredentialFormat.JWT_VC_JSON ->
                    buildJsonObject {
                        put("iss", holderId)
                        put("aud", audience)
                        put("nonce", nonce)
                        put("iat", Clock.System.now().epochSeconds)
                        putJsonObject("vp") {
                            putJsonArray("@context") { add(JsonPrimitive(VcdmProfiles.V1_1_CONTEXT)) }
                            putJsonArray("type") { add(JsonPrimitive("VerifiablePresentation")) }
                            put("holder", holderId)
                            putJsonArray("verifiableCredential") { add(JsonPrimitive(compactCredential)) }
                        }
                    }

                CredentialFormat.JWT_VC_JSON_LD ->
                    buildJsonObject {
                        // VCDM 2.0 requires the base context to be first in the context array.
                        putJsonArray("@context") { add(JsonPrimitive(VcdmProfiles.V2_0_CONTEXT)) }
                        putJsonArray("type") { add(JsonPrimitive("VerifiablePresentation")) }
                        put("holder", holderId)
                        putJsonArray("verifiableCredential") {
                            add(
                                buildJsonObject {
                                    put("@context", VcdmProfiles.V2_0_CONTEXT)
                                    put("id", "data:application/vc+jwt,$compactCredential")
                                    put("type", "EnvelopedVerifiableCredential")
                                },
                            )
                        }
                        put("iss", holderId)
                        put("aud", audience)
                        put("nonce", nonce)
                        put("iat", Clock.System.now().epochSeconds)
                    }

                else ->
                    return Err(
                        IdkError.ILLEGAL_ARGUMENT_ERROR(
                            message = "Unsupported VCDM credential format '${format.value}' for VP production",
                        ),
                    )
            }

        val identifier = credential.holderJwtVpSigningIdentifier ?: return Err(
                IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message = "Cannot create VCDM Verifiable Presentation: an explicit holder signing identifier is missing",
                ),
            )
        return Ok(HolderJwtVpSigningRequest(
                        walletUnitId = credential.holderJwtVpWalletUnitId,
                        payload = vpPayload,
                        keyReference = holderKeyRef,
                        signatureAlgorithm = holderSigningAlgorithm,
                        identifier = identifier,
                        protectedHeader =
                            buildJsonObject {
                                if (format == CredentialFormat.JWT_VC_JSON) {
                                    // VC-JOSE-COSE / VCDM 1.1 JWT VP representation.
                                    put("typ", "JWT")
                                } else {
                                    // VCDM 2.0 VP secured by JOSE.
                                    put("typ", "vp+jwt")
                                    put("cty", "vp")
                                }
                            },
                        operationBinding = credential.holderJwtVpOperationBinding,
                    ))
    }

    private fun validateSignedJwtVp(
        prepared: HolderJwtVpSigningRequest,
        signed: HolderJwtVpSigningResult,
        requireExactPayload: Boolean = false,
    ): IdkResult<String, IdkError> {
        val identifier = prepared.identifier
        val expectedJoseAlgorithm = prepared.signatureAlgorithm.jose?.value
        if (signed.identifier != identifier) {
            return Err(
                IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message = "Holder JWT VP signer returned an identifier different from the admitted holder identifier",
                ),
            )
        }
        val parsed = StrictCompactJws.parse(signed.compactJws).getOrElse { return Err(it) }
        val algorithm = (parsed.protectedHeader["alg"] as? JsonPrimitive)?.contentOrNull
        if (algorithm.isNullOrBlank() || algorithm.equals("none", ignoreCase = true)) {
            return Err(
                IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message = "Cannot create VCDM Verifiable Presentation with missing or alg:none signature algorithm",
                ),
            )
        }
        if (algorithm != expectedJoseAlgorithm) {
            return Err(
                IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message = "Holder JWT VP signer emitted alg '$algorithm', expected '$expectedJoseAlgorithm'",
                ),
            )
        }
        if (parsed.protectedHeader["jwk"] != null) {
            return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Holder JWT VP must not carry embedded JWK trust material"))
        }
        when (identifier) {
            is HolderJwtVpSigningIdentifier.X509 -> {
                val actualChain = (parsed.protectedHeader["x5c"] as? JsonArray)
                    ?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }
                if (parsed.protectedHeader["kid"] != null || actualChain != identifier.certificateChain) {
                    return Err(
                        IdkError.ILLEGAL_ARGUMENT_ERROR(
                            message = "Holder JWT VP protected x5c header must equal the admitted X.509 chain and must not carry kid",
                        ),
                    )
                }
            }

            else -> {
                val actualKid = (parsed.protectedHeader["kid"] as? JsonPrimitive)?.contentOrNull
                if (parsed.protectedHeader["x5c"] != null || actualKid != identifier.value) {
                    return Err(
                        IdkError.ILLEGAL_ARGUMENT_ERROR(
                            message = "Holder JWT VP protected header kid must equal the admitted signing identifier",
                        ),
                    )
                }
            }
        }
        val expectedTyp = (prepared.protectedHeader["typ"] as? JsonPrimitive)?.contentOrNull
        if ((parsed.protectedHeader["typ"] as? JsonPrimitive)?.contentOrNull != expectedTyp) {
            return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Holder JWT VP protected header typ does not match the VCDM format"))
        }
        if (requireExactPayload && parsed.payloadSegment != prepared.payload.toString().encodeToByteArray().encodeToBase64Url()) {
            return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Holder JWT VP signer changed the prepared payload"))
        }
        return Ok(signed.compactJws)
    }

    /**
     * Creates one independently holder-secured Data Integrity VP for one selected Data Integrity
     * VC. OID4VP 1.0 Final uses `ldp_vc` for both the VC and the holder-bound VP; the VCDM type
     * selects assertion versus authentication proof semantics.
     */
    private suspend fun resolveVcdmDataIntegrityPresentation(
        request: ResolvedOid4vpRequest,
        credential: SelectedCredential,
    ): IdkResult<JsonElement, IdkError> {
        val vc = credential.presentation as? JsonObject
            ?: return Err(
                IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message = "Selected ldp_vc credential '${credential.credentialId}' must be a JSON object",
                ),
            )
        if (!credential.dataIntegrityProofApplied) {
            return Err(
                IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message = "Selected ldp_vc credential '${credential.credentialId}' must be holder-bound by the WSCA before response assembly",
                ),
            )
        }
        val classification = VcdmClassifier.classifyDocument(vc).getOrElse { return Err(it) }
        if (classification.kind != VcdmDocumentKind.PRESENTATION || vc["proof"] == null) {
            return Err(
                IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message = "Selected ldp_vc credential '${credential.credentialId}' is not an already-secured VerifiablePresentation",
                ),
            )
        }
        return Ok(vc)
    }

    /**
     * Build the `mso_mdoc` OID4VP presentation: an ISO 18013-5/-7 `DeviceResponse`.
     *
     * The stored [SelectedCredential.presentation] is the issued `IssuerSigned`
     * (base64url(CBOR), OID4VCI §A.4). A bare `IssuerSigned` is NOT a `DeviceResponse`, so the
     * verifier's `DeviceResponseCborCodec` rejects it; the holder must wrap it and add holder
     * binding. Steps:
     *
     *  1. base64url-decode + CBOR-decode the stored `IssuerSigned`; read the issued MSO to learn
     *     the `docType` (and, via the MSO `deviceKeyInfo.deviceKey`, the device key the holder
     *     binds against — resolved inside [MdocOid4vpService]).
     *  2. wrap it in a [Document] (the device-signed half is produced by the signer).
     *  3. derive an ISO 18013-7 presentation definition whose input-descriptor `id` is the
     *     `docType` and whose constraint fields cover every issued element (`$['ns']['element']`),
     *     so all held elements are disclosed for this single-credential request.
     *  4. match document <-> descriptor (derives the device key from the MSO) and call
     *     [MdocOid4vpService.createDeviceResponse], which signs `DeviceAuth` over the §B.2.6
     *     `OpenID4VPHandover` SessionTranscript built from `client_id` + `nonce` + `response_uri`
     *     For `direct_post.jwt`, the handover includes the RFC 7638 thumbprint of the exact
     *     verifier encryption JWK used for the response JWE. The verifier reconstructs the same
     *     transcript via `SessionTranscript.fromOid4vpClientIdAndResponseUri(...)`.
     *  5. submit base64url(CBOR(DeviceResponse)) as the vp_token entry (the form the verifier's
     *     `DeviceResponseCborCodec` decodes; `CredentialFormat.detectFormat` reads it as mso_mdoc).
     */
    private suspend fun resolveMdocPresentation(
        request: ResolvedOid4vpRequest,
        credential: SelectedCredential,
        preparedMdocSigning: PreparedMdocCredentialSigning? = null,
        mdocSignature: MdocCredentialSigningSignature? = null,
        prepareOnly: Boolean = false,
    ): IdkResult<MdocPresentationResolution, IdkError> {
        val nonce =
            request.request.nonce
                ?: return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message =
                            "Cannot create mdoc DeviceResponse for query '${credential.credentialQueryId}': " +
                                "authorization request has no nonce",
                    ),
                )
        // The transcript inputs are response-mode-specific. In particular, DC API uses the
        // validated browser origin carried in an internal marker by the parser, never client_id.
        val clientId = request.request.clientId
        val responseMode = request.request.responseMode ?: ResponseMode.DIRECT_POST.value
        val responseUri = request.request.responseUri
        val redirectUri = request.request.redirectUri
        val callerOrigin =
            request.request.additionalParameters[DIGITAL_CREDENTIAL_ORIGIN_PARAMETER]
                ?.jsonPrimitive
                ?.contentOrNull

        val issuerSignedBytes =
            try {
                credential.presentation.compactStringOrNull()?.decodeFromBase64Url()
                    ?: throw IllegalArgumentException("mso_mdoc presentation must be a JSON string")
            } catch (expected: Exception) {
                return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message =
                            "Stored mso_mdoc credential for query '${credential.credentialQueryId}' is not valid " +
                                "base64url: ${expected.message}",
                    ),
                )
            }

        val issuerSigned: IssuerSigned =
            issuerSignedCborCodec
                .decode(issuerSignedBytes)
                .getOrElse {
                    return Err(
                        IdkError.ILLEGAL_ARGUMENT_ERROR(
                            message =
                                "Failed to CBOR-decode stored IssuerSigned for query " +
                                    "'${credential.credentialQueryId}': ${it.message.defaultMessage}",
                        ),
                    )
                }.value

        val msoPayload =
            issuerSigned.issuerAuth.payload?.value
                ?: return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message = "Stored mso_mdoc credential for query '${credential.credentialQueryId}' has no MSO payload",
                    ),
                )
        val mso =
            mobileSecurityObjectCborCodec
                .decode(msoPayload)
                .getOrElse {
                    return Err(
                        IdkError.ILLEGAL_ARGUMENT_ERROR(
                            message = "Failed to decode MSO for query '${credential.credentialQueryId}': ${it.message.defaultMessage}",
                        ),
                    )
                }.value
        val docType = mso.docType

        val document = Document(docType = docType, issuerSigned = issuerSigned, deviceSigned = null, original = null)

        // Preserve the exact requested elements. For the ISO Presentation Definition profile we
        // reuse its constraints directly. For DCQL, translate namespace/element claim paths to
        // the ISO JSONPath form. In DCQL, absent claims means no selectively-disclosable mdoc
        // elements; only the legacy Presentation Definition path defaults to the full document.
        val presentationDescriptor =
            parsePresentationDefinition(request)
                ?.input_descriptors
                ?.firstOrNull { it.id.toString() == credential.credentialQueryId }
                ?: parsePresentationDefinition(request)?.input_descriptors?.singleOrNull()
        val dcqlCredentialQuery =
            request.dcqlQuery
                ?.credentials
                ?.firstOrNull { it.id == credential.credentialQueryId }
        val requestedDcqlFields =
            dcqlCredentialQuery?.let { query ->
                val options =
                    try {
                        request.credentialDisclosurePathOptions(credential.credentialQueryId)
                    } catch (expected: IllegalArgumentException) {
                        return Err(
                            IdkError.ILLEGAL_ARGUMENT_ERROR(
                                message = "Invalid mso_mdoc claim selection for query '${credential.credentialQueryId}': ${expected.message}",
                            ),
                        )
                    }
                var selectedFields: List<Oid4VPConstraintField>? = null
                for (option in options) {
                    val fields = mutableListOf<Oid4VPConstraintField>()
                    var satisfiable = true
                    for (path in option) {
                        if (path.size != 2 || path.any { component -> component !is JsonPrimitive || !component.isString }) {
                            return Err(
                                IdkError.ILLEGAL_ARGUMENT_ERROR(
                                    message = "mso_mdoc Claims Path Pointer must contain exactly two string components",
                                ),
                            )
                        }
                        val namespace = (path[0] as JsonPrimitive).content
                        val elementIdentifier = (path[1] as JsonPrimitive).content
                        if (issuerSigned.getIssuerSignedItem(NameSpace(namespace), DataElementIdentifier(elementIdentifier)) == null) {
                            satisfiable = false
                        }
                        fields +=
                            Oid4VPConstraintField(
                                path = arrayOf("$['$namespace']['$elementIdentifier']"),
                                intent_to_retain =
                                    query.claims
                                        ?.firstOrNull { it.path.components == path }
                                        ?.intent_to_retain
                                        ?: false,
                            )
                    }
                    if (satisfiable) {
                        selectedFields = fields
                        break
                    }
                }
                selectedFields
                    ?: return Err(
                        IdkError.ILLEGAL_ARGUMENT_ERROR(
                            message = "Stored mso_mdoc credential for query '${credential.credentialQueryId}' does not satisfy any requested DCQL claim set",
                        ),
                    )
            }.orEmpty()
        val constraintFields =
            presentationDescriptor?.constraints?.fields?.toList()
                ?: if (dcqlCredentialQuery != null) {
                    requestedDcqlFields
                } else {
                    (issuerSigned.nameSpaces ?: emptyMap()).flatMap { (nameSpace, items) ->
                        items.map { encoded ->
                            Oid4VPConstraintField(
                                path = arrayOf("$['$nameSpace']['${encoded.data().elementIdentifier}']"),
                                intent_to_retain = false,
                            )
                        }
                    }
                }
        val dcqlRequestsNoSelectiveClaims = dcqlCredentialQuery != null && dcqlCredentialQuery.claims == null
        if (constraintFields.isEmpty() && !dcqlRequestsNoSelectiveClaims) {
            return Err(
                IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message = "Stored mso_mdoc credential for query '${credential.credentialQueryId}' discloses no elements",
                ),
            )
        }

        val mdocAlgorithms =
            presentationDescriptor?.format?.mso_mdoc?.alg
                ?: issuerSigned.issuerAuth.protectedHeader.alg?.let { arrayOf(it.name) }
                ?: return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message =
                            "Cannot create mdoc DeviceResponse for query '${credential.credentialQueryId}': " +
                                "no IssuerAuth COSE algorithm or verifier-supported mso_mdoc algorithm is available",
                    ),
                )
        val presentationDefinition =
            Oid4VPPresentationDefinition(
                id = credential.credentialQueryId,
                input_descriptors =
                    arrayOf(
                        Oid4VPInputDescriptor(
                            id = docType,
                            format = Oid4VPFormat(mso_mdoc = Oid4VPSupportedAlgorithm(alg = mdocAlgorithms)),
                            constraints = Oid4VPConstraints(fields = constraintFields.toTypedArray()),
                        ),
                    ),
            )

        // mdocGeneratedNonce is NOT part of the OID4VP 1.0 final §B.2.6 OpenID4VPHandover
        // (the transcript is [client_id, nonce, jwkThumbprint|null, response_uri]); it only
        // tags the per-document match result and never enters the signed transcript, so a fresh
        // value is fine here.
        val matchResults =
            mdocOid4vpService.matchDocumentsAndDescriptors(
                mdocNonce = Uuid.v4String(),
                applicableDocuments = arrayOf(document),
                presentationDefinition = presentationDefinition,
            )

        // The match result derives the device key from the MSO `deviceKeyInfo.deviceKey`, which is
        // a PUBLIC key carrying only a kid — not the KMS alias/providerId needed to locate the
        // holder's PRIVATE device key for DeviceAuth signing. Overlay the wallet's holder key
        // alias (the same one the proof-of-possession bound at issuance) so the COSE signer can
        // resolve the managed private key. Without this the signer fails with "Need to provide an
        // alias".
        val holderKeyAlias = credential.holderKeyRef
        val signableMatchResults =
            if (!holderKeyAlias.isNullOrBlank()) {
                matchResults
                    .map { match ->
                        if (match.document != null && match.documentError == null) {
                            match.copy(
                                deviceKeyInfo =
                                    KeyInfo(
                                    alias = holderKeyAlias,
                                    keyVisibility = KeyVisibility.PRIVATE,
                                ),
                            )
                        } else {
                            match
                        }
                    }.toTypedArray()
            } else {
                matchResults
            }

        var recipientBinding: PreparedOid4vpJweRecipientBinding? = null
        val verifierEncryptionJwkThumbprint =
            when (ResponseMode.fromValue(responseMode)) {
                ResponseMode.DIRECT_POST_JWT,
                ResponseMode.DC_API_JWT,
                ResponseMode.IAE_POST_JWT -> {
                    val encryptionJwk =
                        request.clientMetadata
                            ?.selectEncryptedResponseJwk()
                            ?: return Err(
                                IdkError.ILLEGAL_ARGUMENT_ERROR(
                                    message =
                                        "Cannot create encrypted mdoc DeviceResponse for query " +
                                            "'${credential.credentialQueryId}': client_metadata.jwks has no " +
                                            "encryption JWK with an alg",
                                ),
                            )
                    if (encryptionJwk.d != null || encryptionJwk.k != null || encryptionJwk.p != null || encryptionJwk.q != null ||
                        encryptionJwk.dP != null || encryptionJwk.dQ != null || encryptionJwk.qInv != null
                    ) {
                        return Err(
                            IdkError.ILLEGAL_ARGUMENT_ERROR(
                                message = "Cannot create mdoc DeviceResponse using a verifier JWK that contains private key material",
                            ),
                        )
                    }
                    val encodedThumbprint =
                        tryGenerateJwkThumbprint(encryptionJwk)
                            .getOrElse { return Err(it) }
                    recipientBinding =
                        PreparedOid4vpJweRecipientBinding(
                            publicJwkJson = Jwk.from(encryptionJwk.toPublicKey()).toJsonString(),
                            rfc7638Thumbprint = encodedThumbprint,
                            keyEncryptionAlgorithm = encryptionJwk.alg!!.value,
                            contentEncryptionAlgorithm =
                                request.clientMetadata?.encryptedResponseEncValuesSupported?.firstOrNull()
                                    ?: JarmConfig.DEFAULT_CONTENT_ENCRYPTION_ALG,
                            responseMode = responseMode,
                            clientId = clientId,
                            authorizationRequestNonce = nonce,
                            responseUri = responseUri,
                            redirectUri = redirectUri,
                            callerOrigin = callerOrigin,
                        )
                    try {
                        encodedThumbprint.decodeFromBase64Url()
                    } catch (expected: Exception) {
                        return Err(
                            IdkError.ILLEGAL_ARGUMENT_ERROR(
                                message =
                                    "Cannot create encrypted mdoc DeviceResponse for query " +
                                        "'${credential.credentialQueryId}': verifier JWK thumbprint is invalid: " +
                                        expected.message,
                            ),
                        )
                    }
                }

                else -> null
            }

        val deviceAuthenticationContext =
            Oid4vpDeviceAuthenticationContext(
                responseMode = responseMode,
                clientId = clientId,
                authorizationRequestNonce = nonce,
                responseUri = responseUri,
                redirectUri = redirectUri,
                callerOrigin = callerOrigin,
                verifierEncryptionJwkThumbprint = verifierEncryptionJwkThumbprint,
            )

        if (prepareOnly) {
            if (holderKeyAlias.isNullOrBlank()) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Selected mdoc credential has no holder key reference"))
            }
            val prepared = mdocOid4vpService.prepareDeviceResponseSignings(
                matchingDocuments = signableMatchResults,
                presentationDefinition = presentationDefinition,
                clientId = clientId,
                responseUri = responseUri,
                authorizationRequestNonce = nonce,
                verifierEncryptionJwkThumbprint = verifierEncryptionJwkThumbprint,
                context = deviceAuthenticationContext,
            ).getOrElse { return Err(it) }
            if (prepared.size != 1 || prepared.single().descriptorId != docType.toString()) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "mdoc signing preparation did not match the selected credential"))
            }
            return Ok(
                MdocPresentationResolution.PreparedSigning(
                    PreparedMdocCredentialSigning(
                        credentialId = credential.credentialId,
                        credentialQueryId = credential.credentialQueryId,
                        docType = docType.toString(),
                        keyReference = holderKeyAlias,
                        signing = prepared.single().signing,
                        recipientBinding = recipientBinding,
                    ),
                ),
            )
        }

        val deviceResponseResult = if (preparedMdocSigning != null || mdocSignature != null) {
            val prepared = preparedMdocSigning
                ?: return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Prepared mdoc signing record is missing"))
            val signature = mdocSignature
                ?: return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Prepared mdoc signature is missing"))
            if (prepared.credentialId != credential.credentialId || prepared.credentialQueryId != credential.credentialQueryId ||
                prepared.docType != docType.toString() || prepared.keyReference != holderKeyAlias) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Prepared mdoc signing does not match the selected credential"))
            }
            mdocOid4vpService.createDeviceResponseWithSignatures(
                matchingDocuments = signableMatchResults,
                presentationDefinition = presentationDefinition,
                clientId = clientId,
                responseUri = responseUri,
                authorizationRequestNonce = nonce,
                verifierEncryptionJwkThumbprint = verifierEncryptionJwkThumbprint,
                context = deviceAuthenticationContext,
                preparedSignings = listOf(PreparedMdocDeviceResponseSigning(docType.toString(), prepared.signing)),
                signatures = listOf(MdocDeviceResponseSignature(docType.toString(), signature.signature)),
            )
        } else {
            if (preparedMdocSigning != null || mdocSignature != null) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Prepared mdoc signing record and signature must be supplied together"))
            }
            try {
                Ok(
                    mdocOid4vpService.createDeviceResponse(
                        matchingDocuments = signableMatchResults,
                        presentationDefinition = presentationDefinition,
                        clientId = clientId,
                        responseUri = responseUri,
                        authorizationRequestNonce = nonce,
                        verifierEncryptionJwkThumbprint = verifierEncryptionJwkThumbprint,
                        context = deviceAuthenticationContext,
                    ),
                )
            } catch (expected: Exception) {
                Err(IdkError.UNKNOWN_ERROR(message = "Failed to build mdoc DeviceResponse for query '${credential.credentialQueryId}': ${expected.message}"))
            }
        }

        val deviceResponse = deviceResponseResult.getOrElse { return Err(it) }
        if (deviceResponse.documents.isNullOrEmpty()) {
            return Err(
                IdkError.UNKNOWN_ERROR(
                    message =
                        "mdoc DeviceResponse for query '${credential.credentialQueryId}' has no documents " +
                            "(documentErrors=${deviceResponse.documentErrors})",
                ),
            )
        }

        val deviceResponseBytes =
            deviceResponseCborCodec
                .encode(deviceResponse)
                .getOrElse {
                    return Err(
                        IdkError.UNKNOWN_ERROR(
                            message =
                                "Failed to CBOR-encode mdoc DeviceResponse for query " +
                                    "'${credential.credentialQueryId}': ${it.message.defaultMessage}",
                        ),
                    )
                }

        return Ok(MdocPresentationResolution.WireValue(deviceResponseBytes.encodeToBase64Url()))
    }

    private fun parsePresentationDefinition(request: ResolvedOid4vpRequest): Oid4VPPresentationDefinition? {
        val definitionElement = request.request.additionalParameters["presentation_definition"] ?: return null
        val normalized: JsonElement =
            when (definitionElement) {
                is JsonPrimitive -> responseJson.parseToJsonElement(definitionElement.content)
                else -> definitionElement
            }
        return responseJson.decodeFromJsonElement(Oid4VPPresentationDefinition.serializer(), normalized)
    }

    private fun JsonElement.compactStringOrNull(): String? =
        (this as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull

    private companion object {
        val responseJson = Json { ignoreUnknownKeys = true }
    }
}
