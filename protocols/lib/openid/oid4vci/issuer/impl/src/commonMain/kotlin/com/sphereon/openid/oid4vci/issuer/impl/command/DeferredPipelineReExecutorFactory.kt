/*
 * (c) 2026 Sphereon International B.V.
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

package com.sphereon.openid.oid4vci.issuer.impl.command

import com.sphereon.data.store.credential.design.CredentialDesignService
import com.sphereon.di.session.SessionScope
import com.sphereon.openid.oid4vci.issuer.attribute.CredentialAttributeContributor
import com.sphereon.openid.oid4vci.issuer.config.Oid4vciIssuerConfigProvider
import com.sphereon.openid.oid4vci.issuer.format.CredentialFormatHandler
import com.sphereon.openid.oid4vci.issuer.lifecycle.Oid4vciIssuanceLifecycleHook
import com.sphereon.openid.oid4vci.issuer.spi.IssuerFederationEntityResolver
import com.sphereon.openid.oid4vci.issuer.store.CredentialIssuanceSessionStore
import com.sphereon.openid.oid4vci.issuer.store.DeferredCredentialStore
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn

/**
 * Factory for the optional [DeferredPipelineReExecutor]. Holds all dependencies that the
 * re-executor needs so [HandleDeferredCredentialRequestCommandImpl] can stay below the detekt
 * `LongParameterList` threshold while keeping Metro DI: every collaborator is still individually
 * injected here, so the graph composition is unchanged.
 *
 * Returns `null` in pure-IDK deployments (no EDK pipeline commands wired in) so the deferred
 * command's PENDING branch falls through to the OID4VCI 1.1 §10.2 `transactionId+interval`
 * response.
 */
@Inject
@SingleIn(SessionScope::class)
class DeferredPipelineReExecutorFactory(
    private val deferredStore: DeferredCredentialStore,
    private val sessionStore: CredentialIssuanceSessionStore,
    private val attributeContributor: CredentialAttributeContributor,
    private val issuerConfigProvider: Oid4vciIssuerConfigProvider,
    /**
     * Format-handler dispatch wiring: the set of [CredentialFormatHandler]s and the optional
     * [CredentialDesignService]. Empty handlers (pure-IDK with no format wired) and `null`
     * design service are valid: re-execution simply skips dispatch when no handler matches.
     */
    private val formatDispatch: FormatDispatch = FormatDispatch(),
    private val lifecycleHook: Oid4vciIssuanceLifecycleHook? = null,
) {
    /**
     * Format-handler dispatch aggregate. Grouped into a single injected type so the factory's
     * primary constructor stays inside the detekt `LongParameterList` threshold.
     */
    @Inject
    data class FormatDispatch(
        val formatHandlers: Set<CredentialFormatHandler> = emptySet(),
        val credentialDesignService: CredentialDesignService? = null,
        /** OpenID Federation membership of the issuer; null when the deployment hosts no federation entities. */
        val federationEntityResolver: IssuerFederationEntityResolver? = null,
    )

    /**
     * Build a [DeferredPipelineReExecutor] when the EDK pipeline commands are wired in;
     * return `null` otherwise.
     *
     * @param tenantIdProvider supplies the current tenant id at call time; closes over the
     *   session execution available to the calling command so this factory itself stays free
     *   of session-context coupling.
     */
    fun create(tenantIdProvider: () -> String?, businessModeProvider: () -> String? = { null }): DeferredPipelineReExecutor? {
        val hook = lifecycleHook ?: return null
        return DeferredPipelineReExecutor(
            deferredStore = deferredStore,
            sessionStore = sessionStore,
            attributeContributor = attributeContributor,
            lifecycleHook = hook,
            issuerConfigProvider = issuerConfigProvider,
            formatHandlers = formatDispatch.formatHandlers,
            credentialDesignService = formatDispatch.credentialDesignService,
            federationEntityResolver = formatDispatch.federationEntityResolver,
            tenantIdProvider = tenantIdProvider,
            businessModeProvider = businessModeProvider,
        )
    }
}
