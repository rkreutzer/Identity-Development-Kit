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

package com.sphereon.openid.oid4vp.verifier.callback

import com.sphereon.openid.oid4vp.universal.GetAuthorizationRequestStatusOutput
import com.sphereon.openid.oid4vp.universal.VerifiedDataMode
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSession

/**
 * Builds the Universal OID4VP status response of an [AuthorizationSession]. The status API and
 * the callback dispatch share it, so both carry the same fields for the same session.
 */
interface AuthorizationSessionStatusResponseMapper {
    /**
     * Maps [session] to its status response. Verified data is only built for a verified session,
     * and only for the representations [verifiedDataModes] selects: an empty list selects none.
     */
    fun build(
        session: AuthorizationSession,
        verifiedDataModes: List<VerifiedDataMode>,
    ): GetAuthorizationRequestStatusOutput
}
