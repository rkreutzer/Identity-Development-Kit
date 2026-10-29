/*
 * Copyright 2026 Sphereon International B.V.
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

package com.sphereon.oauth2.server.authorization.impl.signing

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkError
import com.sphereon.di.session.SessionScope
import com.sphereon.oauth2.server.authorization.impl.command.token.logTokenRefusal
import com.sphereon.oauth2.server.authorization.signing.AsPublishableSigningKeySource
import com.sphereon.oauth2.server.authorization.storage.OAuth2SigningKey
import com.sphereon.oauth2.server.authorization.storage.SigningKeyStore
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding

/**
 * Default [AsPublishableSigningKeySource]: the tenant-wide publishable set from [SigningKeyStore].
 *
 * Every authorization server of the tenant publishes the same keys. Deployments that scope keys to
 * one authorization server replace this binding with `@ContributesBinding(replaces = [...])`.
 */
@Inject
@SingleIn(SessionScope::class)
@ContributesBinding(SessionScope::class, binding = binding<AsPublishableSigningKeySource>())
class DefaultAsPublishableSigningKeySource(
    private val execution: SessionExecution,
    private val signingKeyStore: SigningKeyStore,
) : AsPublishableSigningKeySource {
    override suspend fun listPublishable(tenantId: String): IdkResult<List<OAuth2SigningKey>, IdkError> {
        val result = signingKeyStore.listPublishable(tenantId)
        if (result.isErr) {
            logTokenRefusal(
                execution.log,
                "JWKS publication failed stage=publishable-key-storage error_type=${result.error::class.simpleName}",
            )
            return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = FAILED_TO_LIST_PUBLISHABLE_KEYS))
        }
        return Ok(result.value)
    }

    internal companion object {
        const val FAILED_TO_LIST_PUBLISHABLE_KEYS = "Failed to list publishable signing keys"
    }
}
