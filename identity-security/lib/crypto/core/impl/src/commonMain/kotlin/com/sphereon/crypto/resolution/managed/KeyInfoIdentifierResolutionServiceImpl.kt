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
 *
 */

package com.sphereon.crypto.resolution.managed

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.asErrorResult
import com.sphereon.core.api.asOkResult
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.error.IdkErrorType
import com.sphereon.crypto.core.KeyInfo
import com.sphereon.crypto.core.KeyInfoType
import com.sphereon.crypto.core.KeyType
import com.sphereon.crypto.core.ManagedKeyInfo
import com.sphereon.crypto.core.ManagedKeyInfoType
import com.sphereon.crypto.core.ResolvedKeyInfo
import com.sphereon.crypto.core.kms.KeyManagerService
import com.sphereon.crypto.resolution.IdentifierMethodDefaults
import com.sphereon.crypto.resolution.IdentifierTypeUtils
import com.sphereon.crypto.resolution.managed.ManagedIdentifierServiceAdapter
import com.sphereon.di.session.SessionContext
import com.sphereon.di.session.SessionScope
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.ContributesIntoSet
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding
import software.amazon.app.platform.scope.Scoped
import kotlin.experimental.ExperimentalObjCName
import kotlin.native.ObjCName

@Inject
@SingleIn(SessionScope::class)
@ContributesBinding(SessionScope::class, binding = binding<KeyInfoIdentifierResolutionService>())
@ContributesIntoSet(SessionScope::class, binding = binding<ManagedIdentifierService>())
@OptIn(ExperimentalObjCName::class)
@ObjCName("KeyInfoIdentifierResolutionServiceImpl", exact = true)
class KeyInfoIdentifierResolutionServiceImpl(
    execution: SessionExecution,
    val kms: KeyManagerService,
) : ManagedIdentifierServiceAdapter<ManagedIdentifierKeyResult>(
        supportedIdentifierMethods =
            listOf(
                IdentifierMethodDefaults.KEY,
                IdentifierMethodDefaults.KEY_ALIAS,
                IdentifierMethodDefaults.KID,
                IdentifierMethodDefaults.JWK,
                IdentifierMethodDefaults.COSE_KEY,
            ),
        execution = execution,
        commandId = COMMAND_ID,
    ),
    KeyInfoIdentifierResolutionService,
    Scoped {
    @Suppress("MagicNumber")
    override suspend fun doExecute(
        args: ManagedIdentifierOptsOrResult,
        applyDuring: (ManagedIdentifierOptsOrResult) -> ManagedIdentifierOptsOrResult,
    ): IdkResult<ManagedIdentifierKeyResult, IdkErrorType> {
        log.debug("MANAGED_KEY_IDENTIFIER_RESOLUTION stage=begin")
        if (!supports(args)) {
            log.warn("MANAGED_KEY_IDENTIFIER_RESOLUTION_FAILED stage=argument-type")
            return IdkError
                .COMMAND_ARG_NOT_SUPPORTED_ERROR(message = "Managed identifier opts for Key expected. Type ${args.method ?: args.identifier} not supported")
                .asErrorResult()
        }
        val optsResult = asSupportedOpts(args)
        if (optsResult.isErr) {
            log.warn("MANAGED_KEY_IDENTIFIER_RESOLUTION_FAILED stage=options-normalization")
            return optsResult.error.asErrorResult()
        }

        val opts = optsResult.value
        log.debug("opts.identifier.signatureAlgorithm = ${opts.identifier.signatureAlgorithm}")
        // Resolution policy:
        //  - If the caller supplied a fully-formed key (e.g. via ManagedOptsJwk wrapping a
        //    ResolvedKeyInfo whose key is already populated), respect the supplied key. The
        //    KMS keystore is consulted only when the identifier is alias/kid-only. Substituting
        //    a KMS-resident key in place of an explicitly-supplied one would silently change
        //    which private/public key performs the cryptographic operation.
        //  - Otherwise, look the key up in the KMS keystore.
        var managedKeyInfo =
            if (opts.identifier.key !== null) {
                resolveFromSuppliedKey(opts.identifier)
            } else {
                try {
                    kms.getKey(opts.identifier)
                } catch (expected: Exception) {
                    // Surface lookup failures as IdkResult.Err so JWE/JWS decrypt/verify callers
                    // see a typed error rather than a raw exception bubbling out of the resolver.
                    // Without this, a missing/unknown key throws PKIException and the higher-level
                    // IdkResult-based contract is bypassed.
                    log.warn("MANAGED_KEY_IDENTIFIER_RESOLUTION_FAILED stage=kms-lookup exception=${expected::class.simpleName}")
                    return IdkError
                        .NOT_FOUND_ERROR(
                            resource = "Key",
                            message = "Could not resolve managed key identifier: ${expected.message}",
                        ).asErrorResult()
                }
            }
        log.debug("Retrieved key with signatureAlgorithm = ${managedKeyInfo.signatureAlgorithm}")

        val requestedKid = opts.identifier.kid?.takeIf { it.isNotBlank() }
        if (requestedKid != null && managedKeyInfo.kid != requestedKid) {
            managedKeyInfo = managedKeyInfo.withRequestedKid(requestedKid)
        }

        // A protected JWS alg is only a request. Never rewrite metadata resolved by KMS;
        // the signing/verification boundary validates compatibility separately.

        @Suppress("UNCHECKED_CAST")
        return ManagedIdentifierKeyResult(
            keyInfo = managedKeyInfo as ManagedKeyInfoType<KeyType>,
            context = args.context,
            identifier = managedKeyInfo.key,
        ).asOkResult()
            .also { log.debug("MANAGED_KEY_IDENTIFIER_RESOLUTION stage=complete") }
    }

    private fun ManagedKeyInfoType<*>.withRequestedKid(kid: String): ManagedKeyInfoType<*> =
        ManagedKeyInfo(
            alias = alias,
            providerId = providerId,
            resolvedKeyInfo =
                ResolvedKeyInfo(
                    key = key,
                    signatureAlgorithm = signatureAlgorithm,
                    kid = kid,
                    alias = alias,
                    providerId = providerId,
                    keyVisibility = keyVisibility,
                    keyType = keyType,
                    keyEncoding = keyEncoding,
                    x5c = x5c,
                    opts = opts,
                    noCache = noCache,
                ),
        )

    override suspend fun supports(args: Any): Boolean = supportsManagedIdentifierArgs(args)

    override suspend fun isSupportedIdentifier(identifier: Any): Boolean =
        when (identifier) {
            is KeyInfoType<*> -> true
            is KeyType -> true
            is String -> IdentifierTypeUtils.isKidIdentifier(identifier) || IdentifierTypeUtils.isKeyAliasIdentifier(identifier)
            else -> false
        }

    override suspend fun resolve(opts: ManagedIdentifierOptsOrResult): IdkResult<ManagedIdentifierKeyResult, IdkErrorType> = execute(opts)

    override suspend fun asSupportedOpts(opts: ManagedIdentifierOptsOrResult): IdkResult<ManagedOptsKeyInfo, IdkErrorType> {
        if (!isSupportedOpts(opts)) {
            return IdkError
                .COMMAND_ARG_NOT_SUPPORTED_ERROR(message = "Managed identifier opts or result not supported : ${opts::class.simpleName}, id: ${opts.identifier}")
                .asErrorResult()
        }
        return when (opts) {
            is ManagedIdentifierResult<*> -> {
                ManagedOptsKeyInfo(identifier = opts.keyInfo, context = opts.context, lookup = opts.keyInfo)
            }

            is ManagedOptsKeyInfo -> {
                opts
            }

            is ManagedOptsAlias -> {
                ManagedOptsKeyInfo(
                    identifier = KeyInfo<KeyType>(alias = opts.identifier),
                    context = opts.context,
                    lookup = opts.lookup,
                )
            }

            is ManagedOptsKid -> {
                // Use the lookup as the base identifier and only override the kid field if not present
                val lookupKeyInfo = opts.lookup
                val identifier =
                    if (lookupKeyInfo.kid == null) {
                        // If lookup doesn't have kid, set it from opts.identifier
                        when (lookupKeyInfo) {
                            is ResolvedKeyInfo -> lookupKeyInfo.copy(kid = opts.identifier)
                            is KeyInfo<*> -> lookupKeyInfo.copy(kid = opts.identifier)
                            else -> KeyInfo<KeyType>(kid = opts.identifier, signatureAlgorithm = lookupKeyInfo.signatureAlgorithm)
                        }
                    } else {
                        // Use lookup as-is since it already has the kid
                        lookupKeyInfo
                    }
                ManagedOptsKeyInfo(identifier = identifier, context = opts.context, lookup = lookupKeyInfo)
            }

            is ManagedOptsJwk -> {
                ManagedOptsKeyInfo(
                    identifier = ResolvedKeyInfo.fromKey(opts.identifier),
                    context = opts.context,
                    lookup = opts.lookup,
                )
            }

            is ManagedOptsCoseKey -> {
                ManagedOptsKeyInfo(
                    identifier = ResolvedKeyInfo.fromKey(opts.identifier),
                    context = opts.context,
                    lookup = opts.lookup,
                )
            }

            is ManagedOptsKey -> {
                ManagedOptsKeyInfo(identifier = ResolvedKeyInfo.fromKey(opts.identifier), context = opts.context, lookup = opts.lookup)
            }

            else -> {
                return IdkError
                    .COMMAND_ARG_NOT_SUPPORTED_ERROR(message = "Supplied managed identifier opts are not supported ${opts::class.simpleName}, id: ${opts.identifier}")
                    .asErrorResult()
            }
        }.asOkResult()
    }

    private suspend fun supportsManagedIdentifierArgs(args: Any): Boolean {
        val managedArgs = args as? ManagedIdentifierOptsOrResult ?: return false
        val methodSupported = managedArgs.method?.let { isSupportedIdentifierMethod(it) } ?: true
        return methodSupported && isSupportedIdentifier(managedArgs.identifier)
    }

    /**
     * Wraps a caller-supplied [KeyInfoType] (with key material already present) into a
     * [ManagedKeyInfoType] without touching the KMS keystore. Used when the caller has
     * explicitly provided the key to use; the resolver must respect that exact key.
     *
     * Field handling:
     *  - `alias` reuses the supplied value, falling back to the supplied/derived `kid` (the
     *    key's own identifier), then a synthetic literal. The alias is purely a label on the
     *    in-flight result; it is never used to look up anything in the keystore.
     *  - `providerId` reuses the supplied value, falling back to the registered KMS default
     *    provider so that downstream cryptographic operations (wrap/unwrap/decrypt/derive) can
     *    still pick a provider capable of handling the supplied key material.
     */
    private fun resolveFromSuppliedKey(identifier: KeyInfoType<*>): ManagedKeyInfoType<*> {
        val key = requireNotNull(identifier.key) { "resolveFromSuppliedKey requires identifier.key to be non-null" }
        val alias =
            identifier.alias
                ?: identifier.kid
                ?: key.getKeyId(true)
                ?: SUPPLIED_KEY_ALIAS_FALLBACK
        val providerId =
            identifier.providerId
                ?: runCatching { kms.defaultProviderId() }.getOrNull()
                ?: SUPPLIED_KEY_PROVIDER_LABEL
        val resolvedKeyInfo =
            ResolvedKeyInfo(
                key = key,
                signatureAlgorithm = identifier.signatureAlgorithm,
                kid = identifier.kid ?: key.getKeyId(false),
                alias = alias,
                providerId = providerId,
                keyVisibility = identifier.keyVisibility,
                keyType = identifier.keyType ?: key.getKeyType(),
                keyEncoding = identifier.keyEncoding,
                x5c = identifier.x5c,
            )
        return ManagedKeyInfo(
            alias = alias,
            providerId = providerId,
            resolvedKeyInfo = resolvedKeyInfo,
        )
    }

    companion object {
        const val COMMAND_ID = "crypto.resolution.keyinfo"

        /**
         * Synthetic alias used when a caller supplies key material but no alias/kid; the
         * resolver still needs a non-null label to satisfy [ManagedKeyInfo]'s contract.
         */
        private const val SUPPLIED_KEY_ALIAS_FALLBACK = "supplied-key"

        /**
         * Last-resort provider label used only when a caller supplies key material with no
         * providerId AND no KMS provider is registered yet; downstream operations on this
         * placeholder will fail loudly rather than silently route to an unrelated provider.
         */
        private const val SUPPLIED_KEY_PROVIDER_LABEL = "supplied"
    }
}
