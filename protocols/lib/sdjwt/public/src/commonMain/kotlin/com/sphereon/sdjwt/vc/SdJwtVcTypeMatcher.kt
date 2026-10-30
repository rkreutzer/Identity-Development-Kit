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

package com.sphereon.sdjwt.vc

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.error.IdkError

/**
 * Decides whether an SD-JWT VC type satisfies a set of accepted types.
 */
interface SdJwtVcTypeMatcher {
    /**
     * Matches [vct] against [acceptedVcts].
     *
     * An exact match returns true without any type metadata lookup. Otherwise the type metadata chain is
     * resolved through `extends` and every consulted document is validated: it must name the identifier it
     * was resolved for, satisfy the `#integrity` expression that referenced it, and not close a loop. The
     * whole consulted chain is validated even after an accepted ancestor was found.
     *
     * @param vct The type of the presented credential
     * @param acceptedVcts The types the query accepts, at least one
     * @param vctIntegrity The `vct#integrity` expression of the presented credential, if present
     * @return true when [vct] equals or inherits from an accepted type, false when a complete valid chain
     * contains none, and an error when the chain cannot be resolved or validated
     */
    suspend fun matches(
        vct: String,
        acceptedVcts: List<String>,
        vctIntegrity: String?,
    ): IdkResult<Boolean, IdkError>
}
