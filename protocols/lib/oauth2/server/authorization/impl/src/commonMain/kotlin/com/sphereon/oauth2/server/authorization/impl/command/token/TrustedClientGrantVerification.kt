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

package com.sphereon.oauth2.server.authorization.impl.command.token

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.service.StringResult
import com.sphereon.oauth2.server.authorization.command.CreateRefreshTokenArgs
import com.sphereon.oauth2.server.authorization.command.CreateRefreshTokenCommand
import com.sphereon.oauth2.server.authorization.command.token.GrantContext
import com.sphereon.oauth2.server.authorization.impl.command.putClaims
import com.sphereon.oauth2.server.authorization.model.FederationTokenMetadata
import kotlinx.serialization.json.buildJsonObject
import com.sphereon.oauth2.common.model.ClientAuthenticationConfig
import com.sphereon.oauth2.server.authorization.command.VerifiedAuthorizationCodeGrant
import com.sphereon.oauth2.server.authorization.command.VerifiedClientAuthorization
import com.sphereon.oauth2.server.authorization.command.VerifiedClientCredentialsGrant
import com.sphereon.oauth2.server.authorization.command.VerifyAuthorizationCodeGrantArgs
import com.sphereon.oauth2.server.authorization.command.VerifyAuthorizationCodeGrantCommand
import com.sphereon.oauth2.server.authorization.command.VerifyClientCredentialsGrantArgs
import com.sphereon.oauth2.server.authorization.command.VerifyClientCredentialsGrantCommand

internal suspend fun VerifyClientCredentialsGrantCommand.executeWithTrustedClientAuthorization(
    args: VerifyClientCredentialsGrantArgs,
    clientAuthorization: VerifiedClientAuthorization?,
): IdkResult<VerifiedClientCredentialsGrant, IdkError> =
    if (clientAuthorization != null && this is VerifyClientCredentialsGrantCommandImpl) {
        verifyWithTrustedClientAuthorization(args, clientAuthorization)
    } else {
        execute(args)
    }

internal suspend fun VerifyAuthorizationCodeGrantCommand.executeWithTrustedClientAuthorization(
    args: VerifyAuthorizationCodeGrantArgs,
    clientAuthorization: VerifiedClientAuthorization?,
): IdkResult<VerifiedAuthorizationCodeGrant, IdkError> =
    if (clientAuthorization != null && this is VerifyAuthorizationCodeGrantCommandImpl) {
        verifyWithTrustedClientAuthorization(args, clientAuthorization)
    } else {
        execute(args)
    }

internal suspend fun CreateRefreshTokenCommand.issueForVerifiedAuthorizationCode(
    verified: VerifiedAuthorizationCodeGrant,
    context: GrantContext,
    clientAuthorization: VerifiedClientAuthorization?,
): IdkResult<StringResult, IdkError> =
    if (this is CreateRefreshTokenCommandImpl && (clientAuthorization != null ||
            context.tokenRequest.clientAuthentication is ClientAuthenticationConfig.None)) {
        createAfterVerifiedAuthorizationCode(verified, context, clientAuthorization)
    } else {
        // Contributed implementations retain their public command contract and lifecycle.
        execute(refreshTokenArgsForVerifiedCode(verified, context))
    }

internal fun refreshTokenArgsForVerifiedCode(
    verified: VerifiedAuthorizationCodeGrant,
    context: GrantContext,
): CreateRefreshTokenArgs = CreateRefreshTokenArgs(
    subject = verified.subject,
    clientId = verified.clientId,
    scope = verified.scope,
    resource = verified.codeData.admittedAudiences ?: verified.resource,
    defaultAccessTokenAudience = verified.defaultAccessTokenAudience,
    credentialConfigurationIds = (verified.additionalData["credential_configuration_ids"] as? List<*>)
        ?.filterIsInstance<String>().orEmpty(),
    oid4vciIssuerState = (verified.additionalData["issuer_state"] as? String)?.takeIf(String::isNotBlank),
    dpopJkt = context.proofJkt ?: verified.dpopJkt,
    clientInstanceKeyJkt = context.clientInstanceKeyJkt,
    authTime = verified.codeData.authTime,
    acr = verified.codeData.acr,
    amr = verified.codeData.amr,
    nonce = verified.codeData.nonce,
    loginSessionId = verified.codeData.sessionId,
    federationClaims = FederationTokenMetadata.fromUserClaims(buildJsonObject { putClaims(verified.userClaims) })?.toString(),
)
