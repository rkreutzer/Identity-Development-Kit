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
import com.sphereon.core.api.asErrorResult
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.service.TypedServiceCommandAdapter
import com.sphereon.core.api.validation.validate
import com.sphereon.crypto.core.x509.certificateFromPem
import com.sphereon.crypto.core.x509.x509DerOrPemToPem
import com.sphereon.di.session.SessionScope
import com.sphereon.mdoc.oid4vp.Oid4VPPresentationDefinition
import com.sphereon.mdoc.oid4vp.assertedPathEntry
import com.sphereon.oauth2.common.model.AuthorizationRequest
import com.sphereon.oauth2.common.model.AuthorizationErrorResponse
import com.sphereon.openid.oid4vp.holder.validation.validateOid4vpAuthorizationRequest
import io.konform.validation.Invalid
import com.sphereon.openid.oid4vp.common.ClientIdScheme
import com.sphereon.openid.oid4vp.common.JarSignerMethod
import com.sphereon.openid.oid4vp.common.ParseClientIdArgs
import com.sphereon.openid.oid4vp.common.ParsedClientId
import com.sphereon.openid.oid4vp.common.ParseTransactionDataArgs
import com.sphereon.openid.oid4vp.common.ParseTransactionDataCommand
import com.sphereon.openid.oid4vp.common.ParsedTransactionDataEntry
import com.sphereon.openid.oid4vp.common.ResolveScopeArgs
import com.sphereon.openid.oid4vp.common.ResolveScopeCommand
import com.sphereon.openid.oid4vp.common.ValidateClientIdArgs
import com.sphereon.openid.oid4vp.common.ValidateClientIdCommand
import com.sphereon.openid.oid4vp.common.VerifierAttestation
import com.sphereon.openid.oid4vp.common.verifierInfo
import com.sphereon.openid.oid4vp.dcql.DcqlError
import com.sphereon.openid.oid4vp.dcql.DcqlClaimQuery
import com.sphereon.openid.oid4vp.dcql.DcqlCredentialQuery
import com.sphereon.openid.oid4vp.dcql.DcqlQuery
import com.sphereon.openid.oid4vp.dcql.ClaimsPathPointer
import com.sphereon.openid.oid4vp.dcql.validateDcqlQuery
import com.sphereon.openid.oid4vp.holder.ResolveAuthorizationRequestCommand
import com.sphereon.openid.oid4vp.holder.ResolveAuthorizationRequestCommandService
import com.sphereon.openid.oid4vp.holder.ResolvedOid4vpRequest
import com.sphereon.openid.oid4vp.holder.VerifierInfo
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

import dev.zacsweers.metro.ExposeImplBinding
@Inject
@SingleIn(SessionScope::class)
@ExposeImplBinding
class ResolveAuthorizationRequestCommandImpl(
    private val parseClientIdCommand: com.sphereon.openid.oid4vp.common.ParseClientIdCommand,
    private val validateClientIdCommand: ValidateClientIdCommand,
    private val resolveClientMetadataCommand: com.sphereon.openid.oid4vp.holder.command.ResolveClientMetadataCommand,
    private val parseTransactionDataCommand: ParseTransactionDataCommand,
    private val resolveScopeCommand: ResolveScopeCommand? = null,
    execution: SessionExecution,
) : TypedServiceCommandAdapter<AuthorizationRequest, ResolvedOid4vpRequest, IdkError>(
        commandId = ResolveAuthorizationRequestCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<AuthorizationRequest>(),
        outputTypeToken = typeToken<ResolvedOid4vpRequest>(),
    ),
    ResolveAuthorizationRequestCommand,
    ResolveAuthorizationRequestCommandService {
    override val commandId: String get() = ResolveAuthorizationRequestCommand.COMMAND_ID

    override suspend fun supports(args: Any): Boolean = args is AuthorizationRequest

    override suspend fun resolveAuthorizationRequest(request: AuthorizationRequest): IdkResult<ResolvedOid4vpRequest, IdkError> = execute(request)

    // Everything a holder command fetches runs under the counterparty egress rule, also in the components shared with servers.
    override suspend fun doExecute(
        args: AuthorizationRequest,
        applyDuring: (AuthorizationRequest) -> AuthorizationRequest,
    ): IdkResult<ResolvedOid4vpRequest, IdkError> = withCounterpartyEgress { executeUnderEgressRule(args, applyDuring) }

    private suspend fun executeUnderEgressRule(
        args: AuthorizationRequest,
        applyDuring: (AuthorizationRequest) -> AuthorizationRequest,
    ): IdkResult<ResolvedOid4vpRequest, IdkError> {
        val processedArgs = applyDuring(args)

        // 1. Parse DCQL query - either from dcql_query parameter or resolved from scope
        // Per OpenID4VP 1.0 Section 5.5: Either dcql_query or scope representing a DCQL Query
        // MUST be present, but not both.
        val dcqlQueryFromParam =
            processedArgs.additionalParameters["dcql_query"]?.let { dcqlJsonElement ->
                try {
                    // `dcql_query` may arrive either as:
                    // - a JSON object (when coming from a parsed Request Object/JAR)
                    // - a JSON string containing the JSON object (when passed/merged via query parameters)
                    val normalizedElement: JsonElement =
                        when (dcqlJsonElement) {
                            is JsonPrimitive -> {
                                val raw = dcqlJsonElement.contentOrNull?.trim()
                                if (raw.isNullOrBlank()) {
                                    return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Failed to parse DCQL query: empty dcql_query"))
                                }
                                Json.parseToJsonElement(raw)
                            }

                            else -> {
                                dcqlJsonElement
                            }
                        }

                    val parsedQuery = Json.decodeFromJsonElement(DcqlQuery.serializer(), normalizedElement)

                    // Validate the parsed DCQL query - use fold
                    validate(validateDcqlQuery, parsedQuery) { DcqlError.ValidationError(errors = it) }.fold(
                        success = { parsedQuery },
                        failure = { error ->
                            return Err(
                                IdkError.ILLEGAL_ARGUMENT_ERROR(
                                    message = "Invalid DCQL query: ${error.errors.joinToString { it.message }}",
                                ),
                            )
                        },
                    )
                } catch (expected: Exception) {
                    return Err(
                        IdkError.ILLEGAL_ARGUMENT_ERROR(
                            message = "Failed to parse DCQL query: ${expected.message}",
                        ),
                    )
                }
            }

        // 1b. If no dcql_query, try to resolve from scope (OpenID4VP 1.0 Section 5.5)
        val dcqlQueryFromScope =
            if (dcqlQueryFromParam == null && resolveScopeCommand != null && !processedArgs.scope.isNullOrBlank()) {
                val scopeResult =
                    resolveScopeCommand
                        .execute(ResolveScopeArgs(processedArgs.scope))
                        .getOrElse { return it.asErrorResult() }

                // If scope resolved to a DCQL query, use it
                scopeResult.dcqlQuery?.let { resolvedQuery ->
                    // Validate the resolved DCQL query
                    validate(validateDcqlQuery, resolvedQuery) { DcqlError.ValidationError(errors = it) }.fold(
                        success = { resolvedQuery },
                        failure = { error ->
                            return Err(
                                IdkError.ILLEGAL_ARGUMENT_ERROR(
                                    message = "Invalid DCQL query from scope resolution: ${error.errors.joinToString { it.message }}",
                                ),
                            )
                        },
                    )
                }
            } else {
                null
            }

        // Check that both dcql_query and scope-referencing-DCQL are not present
        // Per OpenID4VP 1.0 Section 5.1: "Either a dcql_query or a scope parameter
        // representing a DCQL Query MUST be present in the Authorization Request, but not both."
        if (dcqlQueryFromParam != null && dcqlQueryFromScope != null) {
            return Err(
                IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message = "Both dcql_query and scope referencing a DCQL query are present. Only one is allowed.",
                ),
            )
        }

        val presentationDefinitionQuery =
            if (dcqlQueryFromParam == null && dcqlQueryFromScope == null) {
                processedArgs.additionalParameters["presentation_definition"]?.let { definition ->
                    presentationDefinitionToDcql(definition).getOrElse { return Err(it) }
                }
            } else {
                null
            }

        // Use one normalized credential-query model for both OID4VP Final/DCQL and the
        // ISO 18013-7 mdoc profile's Presentation Definition input.
        val dcqlQuery = dcqlQueryFromParam ?: dcqlQueryFromScope ?: presentationDefinitionQuery

        // 2. Parse verifier attestations if present (OpenID4VP 1.0 Section 5.1.1)
        val verifierAttestations: List<VerifierAttestation>? = processedArgs.verifierInfo

        // 3. Parse transaction data if present (OpenID4VP 1.0 Section 5.1.2)
        val transactionData: List<ParsedTransactionDataEntry>? =
            processedArgs.additionalParameters["transaction_data"]?.let { transactionDataElement ->
                try {
                    // transaction_data is an array of base64url-encoded JSON strings
                    val encodedEntries = transactionDataElement.jsonArray.map { it.jsonPrimitive.content }

                    parseTransactionDataCommand
                        .execute(ParseTransactionDataArgs(encodedEntries))
                        .getOrElse { error ->
                            return Err(error)
                        }.entries
                } catch (expected: Exception) {
                    return Err(
                        IdkError.ILLEGAL_ARGUMENT_ERROR(
                            message = "Failed to parse transaction_data: ${expected.message}",
                        ),
                    )
                }
            }

        validateTransactionDataHolderBinding(dcqlQuery, transactionData).getOrElse { return Err(it) }

        // 4. Resolve client metadata
        val resolvedMetadata =
            resolveClientMetadataCommand
                .execute(processedArgs)
                .getOrElse { return it.asErrorResult() }

        // 5. Parse client_id to determine scheme
        val prefixParsedClientId =
            parseClientIdCommand
                .execute(ParseClientIdArgs(processedArgs.clientId))
                .getOrElse { return it.asErrorResult() }
        val declaredClientIdScheme =
            processedArgs.additionalParameters["client_id_scheme"]
                ?.jsonPrimitive
                ?.contentOrNull
                ?.let(ClientIdScheme::fromPrefix)
        if (prefixParsedClientId.clientIdScheme != ClientIdScheme.PRE_REGISTERED &&
            declaredClientIdScheme != null &&
            prefixParsedClientId.clientIdScheme != declaredClientIdScheme
        ) {
            return Err(
                IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message =
                        "client_id prefix '${prefixParsedClientId.clientIdScheme.prefix}' conflicts with " +
                            "client_id_scheme '${declaredClientIdScheme.prefix}'",
                ),
            )
        }
        val parsedClientId =
            if (prefixParsedClientId.clientIdScheme == ClientIdScheme.PRE_REGISTERED && declaredClientIdScheme != null) {
                ParsedClientId(
                    clientIdScheme = declaredClientIdScheme,
                    clientId = processedArgs.clientId,
                    clientIdWithScheme = processedArgs.clientId,
                )
            } else {
                prefixParsedClientId
            }

        // 6. Validate client_id according to its scheme
        // If a Request Object (JAR) was used, propagate parsed header context into client_id validation
        val jarUsed =
            processedArgs.additionalParameters["__idk_jar_used"]?.jsonPrimitive?.booleanOrNull
                ?: (processedArgs.request != null || processedArgs.requestUri != null)
        val jarKid = processedArgs.additionalParameters["__idk_jar_kid"]?.jsonPrimitive?.contentOrNull
        val jarTyp = processedArgs.additionalParameters["__idk_jar_typ"]?.jsonPrimitive?.contentOrNull
        val jarX5c =
            processedArgs.additionalParameters["__idk_jar_x5c"]?.let { el ->
                (el as? JsonArray)?.mapNotNull { it.jsonPrimitive.contentOrNull }
            }
        val jarSignerMethod =
            if (jarUsed) {
                JarSignerMethod.detect(x5c = jarX5c, jwk = null, kid = jarKid)
            } else {
                null
            }
        val jarSignerCertificates =
            jarX5c
                ?.mapNotNull { derOrPem ->
                    try {
                        certificateFromPem(x509DerOrPemToPem(derOrPem))
                    } catch (expected: Exception) {
                        log.debug("Failed to parse JAR signer certificate: ${expected.message}")
                        null
                    }
                }?.takeIf { it.isNotEmpty() }

        val validationArgs =
            ValidateClientIdArgs(
                parsedClientId = parsedClientId,
                jarUsed = jarUsed,
                jarSignerMethod = jarSignerMethod,
                jarTypHeader = jarTyp,
                jarSignerKid = jarKid,
                jarSignerCertificates = jarSignerCertificates,
                redirectUri = processedArgs.redirectUri,
                responseUri =
                    processedArgs.additionalParameters["response_uri"]?.let {
                        if (it is kotlinx.serialization.json.JsonPrimitive) {
                            it.content
                        } else {
                            null
                        }
                    },
            )

        val digitalCredentialsOrigin =
            processedArgs.additionalParameters[DIGITAL_CREDENTIAL_ORIGIN_PARAMETER]
                ?.jsonPrimitive
                ?.contentOrNull
        val originBoundDigitalCredentialsRequest = parsedClientId.clientIdScheme == ClientIdScheme.ORIGIN
        if (originBoundDigitalCredentialsRequest) {
            if (
                digitalCredentialsOrigin.isNullOrBlank() ||
                processedArgs.clientId != "origin:$digitalCredentialsOrigin" ||
                (processedArgs.responseMode != "dc_api" && processedArgs.responseMode != "dc_api.jwt") ||
                jarUsed
            ) {
                return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message = "Invalid browser-origin client identity for Digital Credentials API request",
                    ),
                )
            }
        }
        val validationResult =
            if (originBoundDigitalCredentialsRequest) {
                null
            } else {
                validateClientIdCommand
                    .execute(validationArgs)
                    .getOrElse { return it.asErrorResult() }
            }

        // 7. Build verifier info with validation results.
        //
        // displayName / logoUri: OID4VP 1.0 final §11.1 does NOT define these in
        // client_metadata — they're OAuth2 RFC 7591 fields (`client_name`, `logo_uri`)
        // which the spec deliberately doesn't reuse for the verifier metadata surface.
        // Wallets that want a display name/logo should pull them from the trust source
        // (e.g. the verifier's x5c subject DN, an OID Federation entity statement, or
        // a Verifier Attestation JWT). Leaving null here until that source is wired in.
        val clientIdValid = validationResult?.valid ?: true
        val x509ClientIdentifier =
            parsedClientId.clientIdScheme in
                setOf(ClientIdScheme.X509_SAN_DNS, ClientIdScheme.X509_SAN_URI, ClientIdScheme.X509_HASH)
        val verifierInfoResult =
            VerifierInfo(
                clientId = processedArgs.clientId,
                clientIdScheme = parsedClientId.clientIdScheme,
                clientIdValid = clientIdValid,
                clientIdValidationErrors = validationResult?.errors.orEmpty(),
                displayName = null,
                logoUri = null,
                trustRoot = null, // TODO: Will come from identifier resolution trust establishment
                requestObjectCertificateChain =
                    if (jarUsed && clientIdValid && x509ClientIdentifier) jarX5c.orEmpty() else emptyList(),
            )

        // 8. Build resolved request
        return Ok(
            ResolvedOid4vpRequest(
                request = processedArgs,
                dcqlQuery = dcqlQuery,
                clientMetadata = resolvedMetadata.metadata,
                verifierInfo = verifierInfoResult,
                authorizationError = if (validateOid4vpAuthorizationRequest(processedArgs) is Invalid) {
                    AuthorizationErrorResponse(error = "invalid_request", state = processedArgs.state)
                } else {
                    null
                },
                transactionData = transactionData,
                verifierAttestations = verifierAttestations,
            ),
        )
    }

}

/**
 * OpenID4VP 1.0 Final Appendix B.3.3 requires transaction data to be carried in a
 * cryptographically holder-bound presentation. Reject the request during resolution, before the
 * wallet offers credentials or asks the user for consent, when any referenced Credential Query
 * explicitly disables that binding.
 */
internal fun validateTransactionDataHolderBinding(
    dcqlQuery: DcqlQuery?,
    transactionData: List<ParsedTransactionDataEntry>?,
): IdkResult<Unit, IdkError> {
    if (transactionData.isNullOrEmpty()) return Ok(Unit)
    val queriesById = dcqlQuery?.credentials.orEmpty().associateBy { it.id }
    for (entry in transactionData) {
        for (credentialId in entry.transactionData.credentialIds) {
            val query =
                queriesById[credentialId]
                    ?: return Err(
                        IdkError.ILLEGAL_ARGUMENT_ERROR(
                            message =
                                "Transaction data at index ${entry.transactionDataIndex} references unknown " +
                                    "Credential Query '$credentialId'",
                        ),
                    )
            if (!query.require_cryptographic_holder_binding) {
                return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message =
                            "Transaction data at index ${entry.transactionDataIndex} references Credential Query " +
                                "'$credentialId', but require_cryptographic_holder_binding is false",
                    ),
                )
            }
        }
    }
    return Ok(Unit)
}

internal fun presentationDefinitionToDcql(definitionElement: JsonElement): IdkResult<DcqlQuery, IdkError> =
    try {
        val normalized =
            when (definitionElement) {
                is JsonPrimitive -> Json.parseToJsonElement(definitionElement.content)
                else -> definitionElement
            }
        val definition = Json.decodeFromJsonElement<Oid4VPPresentationDefinition>(normalized)
        val credentialQueries =
            definition.input_descriptors.mapIndexed { descriptorIndex, descriptor ->
                require(descriptor.format.mso_mdoc != null) {
                    "The ISO mdoc Presentation Definition descriptor '${descriptor.id}' does not request mso_mdoc"
                }
                val requestedClaims =
                    descriptor.constraints.fields.flatMap { field ->
                        field.path.map { path ->
                            val (namespace, elementIdentifier) = assertedPathEntry(path)
                            DcqlClaimQuery(
                                path =
                                    ClaimsPathPointer(
                                        listOf(
                                            JsonPrimitive(namespace.toString()),
                                            JsonPrimitive(elementIdentifier.toString()),
                                        ),
                                    ),
                                intent_to_retain = field.intent_to_retain,
                            )
                        }
                    }
                DcqlCredentialQuery(
                    // Presentation Exchange descriptor IDs may contain characters (such as '.')
                    // that OID4VP Final explicitly forbids in DCQL Credential Query IDs. This ID
                    // is only the identifier of the normalized internal query; the mdoc doctype
                    // remains the original descriptor ID in meta.
                    id = "presentation_credential_$descriptorIndex",
                    format = "mso_mdoc",
                    meta =
                        buildJsonObject {
                            put("doctype_value", descriptor.id.toString())
                        },
                    claims = requestedClaims,
                )
            }
        if (credentialQueries.isEmpty()) {
            Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Presentation Definition has no input descriptors"))
        } else {
            Ok(DcqlQuery(credentials = credentialQueries))
        }
    } catch (expected: Exception) {
        Err(
            IdkError.ILLEGAL_ARGUMENT_ERROR(
                message = "Failed to parse ISO mdoc Presentation Definition: ${expected.message}",
                throwable = expected,
            ),
        )
    }
