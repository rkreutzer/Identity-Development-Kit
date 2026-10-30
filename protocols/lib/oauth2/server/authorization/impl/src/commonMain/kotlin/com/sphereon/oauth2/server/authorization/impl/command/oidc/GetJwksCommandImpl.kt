/*
 * Copyright 2023-2026 Sphereon International B.V.
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

package com.sphereon.oauth2.server.authorization.impl.command.oidc

import com.sphereon.oauth2.server.authorization.impl.command.token.logTokenRefusal
import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.service.TypedServiceCommandAdapter
import com.sphereon.crypto.core.jose.Jwk
import com.sphereon.crypto.resolution.managed.ManagedIdentifierOpts
import com.sphereon.crypto.resolution.managed.ManagedOptsKeyInfo
import com.sphereon.crypto.resolution.managed.MultiManagedIdentifierService
import com.sphereon.crypto.resolution.tryManagedIdentifierToJwk
import com.sphereon.di.context.IdentityConstants
import com.sphereon.di.session.SessionScope
import com.sphereon.oauth2.server.authorization.command.GetJwksArgs
import com.sphereon.oauth2.server.authorization.command.GetJwksCommand
import com.sphereon.oauth2.server.authorization.command.JwksResult
import com.sphereon.oauth2.server.authorization.signing.AsPublishableSigningKeySource
import com.sphereon.oauth2.server.authorization.signing.AsSigningKeyPublicJwkResolver
import com.sphereon.oauth2.server.authorization.storage.OAuth2SigningKey
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import kotlin.experimental.ExperimentalObjCName
import kotlin.native.ObjCName

import dev.zacsweers.metro.ExposeImplBinding
/**
 * Implementation of GetJwksCommand.
 *
 * Returns every publishable signing key for the resolved tenant — i.e. the highest-priority
 * `ACTIVE` key plus any `LEGACY` keys that still verify in-flight tokens issued before the
 * most recent rotation. RPs cache the JWKS and look up by `kid`, so as long as the tenant's
 * key history is in the store, every issued token's verification key is reachable.
 *
 * The keys come from [AsPublishableSigningKeySource]. The default source publishes the
 * tenant-wide set from the signing-key store; a deployment hosting several authorization
 * servers in one tenant binds a source scoped to the selected server.
 *
 * Replaces the earlier single-`serverIdentifier`-by-alias model. Multi-key publication is
 * required for safe rotation: an RP that fetched the previous JWKS still has the LEGACY key
 * for verifying tokens issued before the rotation completed.
 */
@Inject
@SingleIn(SessionScope::class)
@OptIn(ExperimentalObjCName::class)
@ObjCName("GetJwksCommandImpl", exact = true)
@ExposeImplBinding
class GetJwksCommandImpl(
    execution: SessionExecution,
    private val publishableSigningKeySource: AsPublishableSigningKeySource,
    private val multiManagedIdentifierService: Lazy<MultiManagedIdentifierService>,
    private val signingKeyPublicJwkResolver: AsSigningKeyPublicJwkResolver? = null,
) : TypedServiceCommandAdapter<GetJwksArgs, JwksResult, IdkError>(
        commandId = GetJwksCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<GetJwksArgs>(),
        outputTypeToken = typeToken<JwksResult>(),
    ),
    GetJwksCommand {
    override val commandId: String get() = GetJwksCommand.COMMAND_ID

    override suspend fun supports(args: Any): Boolean = args is GetJwksArgs

    override suspend fun doExecute(
        args: GetJwksArgs,
        applyDuring: (GetJwksArgs) -> GetJwksArgs,
    ): IdkResult<JwksResult, IdkError> {
        applyDuring(args)
        return executeInternal()
    }

    private suspend fun executeInternal(): IdkResult<JwksResult, IdkError> {
        val tenantId = execution.tenantId
        if (tenantId.isBlank() || tenantId == IdentityConstants.ANONYMOUS_TENANT_ID) {
            // Tenant resolution (domain/path first) must have established a real tenant before a JWKS
            // request reaches here; there is NO "default" tenant fallback. A blank/anonymous tenant is
            // a bug (a request bypassed Layer-1 resolution) — fail closed rather than publish another
            // tenant's keys or an empty set under a synthetic "default".
            logTokenRefusal(execution.log, "JWKS publication refused stage=tenant-resolution")
            return Err(
                IdkError.INVALID_STATE(
                    message =
                        "JWKS publication requires a resolved tenant; session tenant is " +
                            "'${tenantId.ifBlank { "<blank>" }}'.",
                ),
            )
        }
        // Publish whatever signing keys the source reports as PROVISIONED and publishable for this
        // tenant (and, for a scoped source, for the selected authorization server). No self-seeding
        // here: a durable AS signing key is provisioned explicitly at tenant registration. An empty
        // set is the documented response shape when no key is registered yet.
        val publishableResult = publishableSigningKeySource.listPublishable(tenantId)
        if (publishableResult.isErr) {
            // The source owns the refusal reason; its typed error is returned unchanged.
            return Err(publishableResult.error)
        }
        val publishable = publishableResult.value
        if (publishable.isEmpty()) {
            // Empty JWKS is the documented response shape when no key is registered; RPs
            // treat it as "no public verification key available". Keeps the endpoint healthy
            // during pre-bootstrap or post-emergency-revoke states.
            return Ok(JwksResult(keys = emptyList()))
        }

        val publishedJwks = mutableListOf<Jwk>()
        for (key in publishable) {
            // A deployment resolver is authoritative. Falling back to the local provider registry
            // after it returns null would turn a routed KMS denial into an alternate key lookup.
            val jwk =
                if (signingKeyPublicJwkResolver != null) {
                    signingKeyPublicJwkResolver.resolve(key)
                } else {
                    key.resolveAsPublicJwk()
                }
            if (jwk == null) {
                logTokenRefusal(execution.log, "JWKS publication refused stage=public-key-resolution")
                continue
            }
            publishedJwks.add(jwk)
        }
        return Ok(JwksResult(keys = publishedJwks))
    }

    /**
     * Resolve a single [OAuth2SigningKey] into the public-only JWK that JWKS consumers need.
     * Pins the advertised `kid` to the entry's [OAuth2SigningKey.kid] so RPs that look up by
     * `kid` from the JWS header find the right entry even when the underlying key material's
     * computed `kid` differs.
     *
     * Returns null when the resolution fails for this individual key — a per-key failure
     * should not blank out the whole JWKS, since callers downstream expect at least the
     * still-resolvable keys to publish. The failed key surfaces as a missing-kid in any RP
     * verification attempt, which is the correct signal: the operator sees a kid mismatch
     * in their RP logs and can investigate.
     */
    private suspend fun OAuth2SigningKey.resolveAsPublicJwk(): Jwk? {
        // Preserve providerId/algorithm from the durable SigningKeyStore row. Fresh tenant AS
        // keys are provisioned into the tenant-specific provider, so alias-only lookup would
        // resolve against the wrong provider and publish an empty JWKS.
        val identifier: ManagedIdentifierOpts = ManagedOptsKeyInfo(identifier = keyInfo)
        val resolveResult = multiManagedIdentifierService.value.resolve(identifier)
        if (!resolveResult.isOk) return null
        val jwkResult = tryManagedIdentifierToJwk(resolveResult.value).getOrNull() ?: return null
        val publicJwk = jwkResult.identifier.toPublicKey() as? Jwk ?: return null
        return if (publicJwk.kid == kid) publicJwk else publicJwk.copy(kid = kid)
    }
}
