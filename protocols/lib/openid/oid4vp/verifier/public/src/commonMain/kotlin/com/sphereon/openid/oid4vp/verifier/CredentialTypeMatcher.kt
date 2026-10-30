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

package com.sphereon.openid.oid4vp.verifier

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.error.IdkError
import com.sphereon.openid.oid4vp.dcql.DcqlCredentialQuery
import kotlinx.serialization.json.JsonObject

/**
 * Decides whether an authenticated credential satisfies the credential type constraint of its DCQL query.
 */
interface CredentialTypeMatcher {
    /**
     * Matches [credential] against the type constraint in [query]: `vct_values` for `dc+sd-jwt`, and
     * `type_values` for `jwt_vc_json` and `ldp_vc`.
     *
     * [credential] is the body of the credential whose authenticity was already established: the full
     * payload of an SD-JWT VC, or the credential object of a W3C credential. For W3C credentials the
     * types of the credential root are fully expanded through JSON-LD, and a type no context defines
     * stays as written.
     *
     * @return true when the credential satisfies the query, false when it is of another type, and an
     * error when the type could not be determined, for instance because type metadata or a JSON-LD
     * context cannot be loaded, or the query format has no type constraint handled here
     */
    suspend fun matches(
        credential: JsonObject,
        query: DcqlCredentialQuery,
    ): IdkResult<Boolean, IdkError>
}
