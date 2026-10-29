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

package com.sphereon.openid.oid4vci.rest.impl

import com.sphereon.core.api.conf.ConfigLevel
import com.sphereon.core.api.conf.PrincipalConfigService
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.di.session.SessionScope
import com.sphereon.openid.oid4vci.rest.Oid4vciRestConfig
import com.sphereon.openid.oid4vci.rest.Oid4vciRestConfigProvider
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding

/**
 * Config-driven implementation of [Oid4vciRestConfigProvider].
 *
 * Reads from the config service using the `sphereon.oid4vci.rest` namespace.
 */
@Inject
@SingleIn(SessionScope::class)
@ContributesBinding(SessionScope::class, binding = binding<Oid4vciRestConfigProvider>())
class DefaultOid4vciRestConfigProvider(
    private val execution: SessionExecution,
) : Oid4vciRestConfigProvider {
    private val configService: PrincipalConfigService
        get() = execution.conf.conf(ConfigLevel.PRINCIPAL) as PrincipalConfigService

    override fun getConfig(): Oid4vciRestConfig =
        Oid4vciRestConfig(
            externalBaseUrl = configService.getPropertyAsString("$NAMESPACE.externalBaseUrl"),
            allowProcessLocalRequestStore =
                configService.getPropertyAsString("$NAMESPACE.requests.allowProcessLocalStore")?.trim().equals("true", ignoreCase = true),
        )

    companion object {
        const val NAMESPACE = "oid4vci.rest"
    }
}
