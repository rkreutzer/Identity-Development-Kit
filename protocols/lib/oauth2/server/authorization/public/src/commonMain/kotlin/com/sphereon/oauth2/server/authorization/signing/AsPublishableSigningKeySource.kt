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

package com.sphereon.oauth2.server.authorization.signing

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.error.IdkError
import com.sphereon.oauth2.server.authorization.storage.OAuth2SigningKey

/**
 * Supplies the signing keys an authorization server publishes in its JWKS.
 *
 * The publishable set is every `ACTIVE` key plus every `LEGACY` key that still verifies tokens
 * issued before a rotation, in priority-descending order so JWKS consumers see the current signer
 * first. `DISABLED` keys are never publishable.
 *
 * The default implementation returns the tenant-wide publishable set from the signing-key store.
 * A deployment that hosts several authorization servers in one tenant replaces it with a source
 * that restricts the set to the keys of the authorization server selected for the current session.
 *
 * An empty list is a valid answer: the JWKS endpoint then publishes `keys: []`. An error refuses
 * the JWKS response and is returned to the caller unchanged.
 */
interface AsPublishableSigningKeySource {
    suspend fun listPublishable(tenantId: String): IdkResult<List<OAuth2SigningKey>, IdkError>
}
