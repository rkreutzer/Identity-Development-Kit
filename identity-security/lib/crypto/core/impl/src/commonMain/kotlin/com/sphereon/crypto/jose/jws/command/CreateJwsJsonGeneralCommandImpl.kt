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

@file:Suppress("TooGenericExceptionCaught")

package com.sphereon.crypto.jose.jws.command

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.asOkResult
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.service.TypedServiceCommandAdapter
import com.sphereon.crypto.core.KeyInfo
import com.sphereon.crypto.core.KeyInfoType
import com.sphereon.crypto.core.KeyType
import com.sphereon.crypto.core.KeyVisibility
import com.sphereon.crypto.core.interop.toKeyInfoJwk
import com.sphereon.crypto.core.kms.command.CreateRawSignatureArgs
import com.sphereon.crypto.core.kms.command.CreateRawSignatureCommand
import com.sphereon.crypto.jose.jws.JwsJsonGeneral
import com.sphereon.crypto.jose.jws.assembleGeneral
import com.sphereon.crypto.jose.jws.command.CreateJwsJsonArgs
import com.sphereon.crypto.jose.jws.command.CreateJwsJsonGeneralCommand
import com.sphereon.crypto.jose.jws.command.PrepareJwsCommand
import com.sphereon.crypto.resolution.managed.ManagedIdentifierKeyResult
import com.sphereon.crypto.resolution.managed.ManagedIdentifierOptsOrResult
import com.sphereon.crypto.resolution.managed.ManagedOptsAlias
import com.sphereon.crypto.resolution.managed.ManagedOptsKeyInfo
import com.sphereon.di.session.SessionContext
import com.sphereon.di.session.SessionScope
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlin.experimental.ExperimentalObjCName
import kotlin.native.ObjCName

import dev.zacsweers.metro.ExposeImplBinding
/**
 * Command implementation for creating general JSON JWS
 */
@Inject
@SingleIn(SessionScope::class)
@OptIn(ExperimentalObjCName::class)
@ObjCName("CreateJwsJsonGeneralCommandImpl", exact = true)
@ExposeImplBinding
class CreateJwsJsonGeneralCommandImpl(
    execution: SessionExecution,
    private val prepareJwsCommand: PrepareJwsCommand,
    private val createRawSignatureCommand: CreateRawSignatureCommand,
) : TypedServiceCommandAdapter<CreateJwsJsonArgs, JwsJsonGeneral, IdkError>(
        commandId = CreateJwsJsonGeneralCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<CreateJwsJsonArgs>(),
        outputTypeToken = typeToken<JwsJsonGeneral>(),
    ),
    CreateJwsJsonGeneralCommand {
    override val commandId: String get() = CreateJwsJsonGeneralCommand.COMMAND_ID

    override suspend fun doExecute(
        args: CreateJwsJsonArgs,
        applyDuring: (CreateJwsJsonArgs) -> CreateJwsJsonArgs,
    ): IdkResult<JwsJsonGeneral, IdkError> {
        val appliedArgs = applyDuring(args)

        // Prepare the JWS object
        val prepareResult = prepareJwsCommand.execute(appliedArgs)
        if (prepareResult.isErr) {
            log.error("JWS signing failed command=$commandId stage=preparation idk_code=${prepareResult.error.code}")
            return IdkResult.err(prepareResult.error)
        }

        val prepared = prepareResult.value
        val resolvedKey = (prepared.identifier as ManagedIdentifierKeyResult).keyInfo
        val headerAlgorithm = prepared.jws.protectedHeader?.get("alg")?.jsonPrimitive?.contentOrNull
        val managedSelection =
            try {
                managedSigningSelector(appliedArgs.issuer, resolvedKey).also { selector ->
                    if (selector != null) {
                        resolvedKey.jwsSigningAlgorithmCompatibilityFailure(headerAlgorithm)?.let { failure ->
                            throw IllegalArgumentException(failure)
                        }
                    }
                }
            } catch (expected: IllegalArgumentException) {
                log.warn("JWS signing refused command=$commandId stage=managed-key-selection error_type=IllegalArgumentException")
                return IdkResult.err(IdkError.fromString("Invalid managed signing selection: ${expected.message}", exception = expected))
            }

        // Sign the input
        // Execute through the public KMS command binding. That binding resolves via the
        // session-scoped command registry, so route-only workloads (for example tenant-AS)
        // honor transport.routing.modules.kms.services.signature instead of accidentally
        // selecting an in-process software provider from SignatureService/KeyManagerService.
        val signatureResult =
            try {
                createRawSignatureCommand.execute(
                    CreateRawSignatureArgs(
                        keyInfo = managedSelection ?: resolvedKey,
                        input = prepared.signingInput,
                        requireX5Chain = false,
                    ),
                )
            } catch (cancelled: kotlinx.coroutines.CancellationException) {
                throw cancelled
            } catch (expected: Exception) {
                log.error("JWS signing failed command=$commandId stage=raw-signing error_type=${expected::class.simpleName}")
                return IdkResult.err(IdkError.fromString("Failed to create signature: ${expected.message}", exception = expected))
            }
        val signatureBytes =
            signatureResult.getOrElse { error ->
                log.error("JWS signing failed command=$commandId stage=raw-signing idk_code=${error.code}")
                return IdkResult.err(
                    IdkError.fromString(
                        "Failed to create signature: ${error.message.defaultMessage}",
                        exception = error.exception as? Exception,
                    ),
                )
            }.signature

        if (managedSelection != null) {
            // The managed signer may be remote or non-exportable. Its output must still match
            // the public material used to prepare this JWS; an alias changing between lookup
            // and signing must never return a token signed by a different key.
            val matchesPreparedKey =
                try {
                    verifyManagedJwsSigningResult(
                        keyInfo = resolvedKey,
                        headerAlg = headerAlgorithm,
                        input = prepared.signingInput,
                        signature = signatureBytes,
                    )
                } catch (cancelled: kotlinx.coroutines.CancellationException) {
                    throw cancelled
                } catch (expected: Exception) {
                    log.error("JWS signing failed command=$commandId stage=public-key-consistency error_type=${expected::class.simpleName}")
                    return IdkResult.err(IdkError.fromString("Managed signature verification failed: ${expected.message}", exception = expected))
                }
            if (!matchesPreparedKey) {
                log.error("JWS signing failed command=$commandId stage=public-key-consistency")
                return IdkResult.err(IdkError.fromString("Managed signature does not match the prepared public key"))
            }
        }

        return prepared.assembleGeneral(signatureBytes).asOkResult()
    }
}

/** Keep a caller's explicit managed selector separate from the public JWS projection. */
internal fun managedSigningSelector(
    issuer: ManagedIdentifierOptsOrResult?,
    resolved: KeyInfoType<*>,
): KeyInfoType<*>? {
    val requested = when (issuer) {
        is ManagedOptsAlias -> {
            require(issuer.lookup.key == null) { "Managed alias lookup cannot include inline key material" }
            require(issuer.lookup.alias == null || issuer.lookup.alias == issuer.identifier) {
                "Managed alias lookup identity conflict"
            }
            KeyInfo<KeyType>(
                alias = issuer.identifier,
                kid = issuer.lookup.kid,
                opts = issuer.lookup.opts,
                keyVisibility = KeyVisibility.PRIVATE,
                signatureAlgorithm = issuer.lookup.signatureAlgorithm,
                providerId = issuer.lookup.providerId,
                keyType = issuer.lookup.keyType,
                keyEncoding = issuer.lookup.keyEncoding,
                noCache = issuer.lookup.noCache,
            )
        }
        is ManagedOptsKeyInfo -> issuer.identifier
        else -> return null
    }
    // Supplied material, including public-only material, remains authoritative. Never turn it
    // into a keystore selector simply because it also contains an alias or provider label.
    if (requested.key != null) return null
    require(requested.providerId == null || requested.providerId == resolved.providerId) { "Provider identity conflict" }
    require(requested.alias == null || requested.alias == resolved.alias) { "Managed key alias conflict" }
    // Preserve the protocol kid selected by the caller/AS signing-key store. It is a provider
    // identity, not necessarily the JWK thumbprint: Azure Key Vault, software stores and other
    // providers are allowed to expose a stable alias-native kid for the same public key. The
    // signing provider validates an alias+kid compound selector before cryptographic work, so
    // retaining that kid both preserves the wire-visible identity and still fails closed on a
    // contradictory pair.
    val canonicalJwkKid = toKeyInfoJwk(resolved).key?.kid?.takeIf { it.isNotBlank() }
    val selectorKid = requested.kid ?: resolved.kid ?: canonicalJwkKid
    require(!resolved.alias.isNullOrBlank() || selectorKid != null) { "Resolved managed key has no usable selector" }
    return KeyInfo<KeyType>(
        kid = selectorKid,
        alias = resolved.alias,
        providerId = resolved.providerId,
        keyVisibility = KeyVisibility.PRIVATE,
        signatureAlgorithm = requested.signatureAlgorithm ?: resolved.signatureAlgorithm,
        keyType = resolved.keyType,
        opts = resolved.opts,
    )
}
