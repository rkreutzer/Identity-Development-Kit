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

package com.sphereon.openid.oid4vp.verifier.impl

import com.sphereon.di.session.SessionScope
import com.sphereon.openid.oid4vc.common.SessionError
import com.sphereon.openid.oid4vp.universal.AuthorizationValidationSummary
import com.sphereon.openid.oid4vp.universal.GetAuthorizationRequestStatusOutput
import com.sphereon.openid.oid4vp.universal.VerifiedDataMode
import com.sphereon.openid.oid4vp.universal.verificationBinding
import com.sphereon.openid.oid4vp.verifier.callback.AuthorizationSessionStatusResponseMapper
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSession
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding

@Inject
@SingleIn(SessionScope::class)
@ContributesBinding(SessionScope::class, binding = binding<AuthorizationSessionStatusResponseMapper>())
class AuthorizationSessionStatusResponseMapperImpl : AuthorizationSessionStatusResponseMapper {
    override fun build(
        session: AuthorizationSession,
        verifiedDataModes: List<VerifiedDataMode>,
    ): GetAuthorizationRequestStatusOutput =
        GetAuthorizationRequestStatusOutput(
            correlationId = session.correlationId,
            queryId = session.queryId,
            status = session.status,
            lastUpdated = session.updatedAt,
            sessionId = session.sessionId,
            verifierId = session.verifierId,
            createdAt = session.createdAt,
            expiresAt = session.expiresAt,
            error = session.error?.let { error -> SessionError(code = error.code, message = error.message) },
            verifiedData = buildVerifiedData(session, verifiedDataModes),
            validation = authorizationValidationSummaryOf(session),
            verificationBinding = session.verificationBinding(),
        )
}

/**
 * Summarizes the validation the verifier stored on [session], or null when none has run.
 *
 * Sourced from the stored validation result rather than from the verified data: a rejected session
 * has no verified data at all, which is precisely the case a relying party needs the summary for.
 */
internal fun authorizationValidationSummaryOf(session: AuthorizationSession): AuthorizationValidationSummary? =
    session.validationResult?.let { validationResult ->
        AuthorizationValidationSummary(
            valid = validationResult.valid,
            rejections = validationResult.rejections,
        )
    }
