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

package com.sphereon.openid.oid4vci.holder.impl

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.service.TypedServiceCommandAdapter
import com.sphereon.di.session.SessionScope
import com.sphereon.ktor.http.client.provider.withCounterpartyEgress
import com.sphereon.ktor.http.client.provider.HttpClientFactory
import com.sphereon.ktor.http.client.provider.HttpClientOptions
import com.sphereon.ktor.http.client.provider.counterpartyEgress
import com.sphereon.openid.oid4vci.common.Oid4vciJson
import com.sphereon.openid.oid4vci.common.Oid4vciUrls
import com.sphereon.openid.oid4vci.common.model.CredentialIssuerMetadata
import com.sphereon.openid.oid4vci.holder.Oid4vciHolderConfig
import com.sphereon.openid.oid4vci.holder.ResolveIssuerMetadataArgs
import com.sphereon.openid.oid4vci.holder.ResolveIssuerMetadataCommand
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.ExposeImplBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.contentType
import io.ktor.http.isSuccess

@Inject
@SingleIn(SessionScope::class)
@ContributesBinding(SessionScope::class, binding = binding<ResolveIssuerMetadataCommand>())
@ExposeImplBinding
class ResolveIssuerMetadataCommandImpl(
    execution: SessionExecution,
    private val httpClientFactory: HttpClientFactory,
    private val signedMetadataVerifier: SignedMetadataVerifier,
    private val config: Oid4vciHolderConfig,
) : TypedServiceCommandAdapter<ResolveIssuerMetadataArgs, CredentialIssuerMetadata, IdkError>(
        commandId = ResolveIssuerMetadataCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<ResolveIssuerMetadataArgs>(),
        outputTypeToken = typeToken<CredentialIssuerMetadata>(),
    ),
    ResolveIssuerMetadataCommand {
    override val commandId: String get() = ResolveIssuerMetadataCommand.COMMAND_ID

    override suspend fun supports(args: Any): Boolean = args is ResolveIssuerMetadataArgs

    // Everything a holder command fetches runs under the counterparty egress rule, also in the components shared with servers.
    override suspend fun doExecute(
        args: ResolveIssuerMetadataArgs,
        applyDuring: (ResolveIssuerMetadataArgs) -> ResolveIssuerMetadataArgs,
    ): IdkResult<CredentialIssuerMetadata, IdkError> = withCounterpartyEgress { executeUnderEgressRule(args, applyDuring) }

    private suspend fun executeUnderEgressRule(
        args: ResolveIssuerMetadataArgs,
        applyDuring: (ResolveIssuerMetadataArgs) -> ResolveIssuerMetadataArgs,
    ): IdkResult<CredentialIssuerMetadata, IdkError> {
        val applied = applyDuring(args)
        val issuerUrl = Oid4vciUrls.buildIssuerUrl(applied.issuerUrl)

        val wellKnownUrl = Oid4vciUrls.buildWellKnownUrl(applied.issuerUrl)

        log.debug("Fetching issuer metadata from: $wellKnownUrl")

        val httpClient =
            try {
                httpClientFactory.createClient(HttpClientOptions.createDefault().counterpartyEgress())
            } catch (expected: Exception) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Failed to create HTTP client: ${expected.message}", throwable = expected))
            }

        return try {
            val response = httpClient.get(wellKnownUrl)

            if (!response.status.isSuccess()) {
                return Err(
                    IdkError.fromString(
                        message = "Failed to fetch issuer metadata from $wellKnownUrl: HTTP ${response.status.value}",
                        code = "METADATA_FETCH_FAILED",
                    ),
                )
            }

            val bodyText = response.bodyAsText()

            // Detect signed metadata response (application/jwt or JWT-shaped body)
            val contentType = response.contentType()?.toString() ?: ""
            val isJwt =
                contentType.contains("application/jwt") ||
                    contentType.contains("openidvci-issuer-metadata+jwt") ||
                    SignedMetadataVerifier.isJwtResponse(bodyText)

            val metadata =
                if (isJwt) {
                    signedMetadataVerifier
                        .verifyAndExtract(bodyText, issuerUrl)
                        .getOrElse { return Err(it) }
                } else {
                    val unsignedMetadata =
                        try {
                            Oid4vciJson.lenient.decodeFromString(CredentialIssuerMetadata.serializer(), bodyText)
                        } catch (expected: Exception) {
                            return Err(
                                IdkError.ILLEGAL_ARGUMENT_ERROR(
                                    message = "Failed to parse issuer metadata JSON: ${expected.message}",
                                    throwable = expected,
                                ),
                            )
                        }
                    if (unsignedMetadata.signedMetadata != null) {
                        val signedResult =
                            signedMetadataVerifier.verifyAndExtract(
                                unsignedMetadata.signedMetadata!!,
                                issuerUrl,
                            )
                        if (signedResult.isOk) {
                            return Ok(signedResult.value)
                        }
                        // The issuer published signed_metadata — that is a commitment to signing.
                        // If verification fails, this is an error, not a fallback scenario.
                        return Err(
                            IdkError.fromString(
                                message = "Issuer published signed_metadata but verification failed: ${signedResult.error.message.defaultMessage}",
                                code = "SIGNED_METADATA_VERIFICATION_FAILED",
                            ),
                        )
                    }

                    // Issuer did not provide signed_metadata at all
                    if (config.requireVerifiedSignedMetadata) {
                        return Err(
                            IdkError.fromString(
                                message = "Holder requires signed metadata but issuer did not provide signed_metadata",
                                code = "SIGNED_METADATA_REQUIRED",
                            ),
                        )
                    }

                    unsignedMetadata
                }

            // OID4VCI 12.2.4 requires simple string comparison without normalization.
            if (metadata.credentialIssuer != issuerUrl) {
                return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message = "credential_issuer in metadata (${metadata.credentialIssuer}) does not match requested issuer URL ($issuerUrl)",
                    ),
                )
            }

            log.debug("Successfully resolved issuer metadata for: $issuerUrl")
            Ok(metadata)
        } catch (expected: Exception) {
            Err(
                IdkError.fromString(
                    message = "Network error fetching issuer metadata from $wellKnownUrl: ${expected.message}",
                    code = "METADATA_NETWORK_ERROR",
                    exception = expected,
                ),
            )
        } finally {
            httpClient.close()
        }
    }
}
