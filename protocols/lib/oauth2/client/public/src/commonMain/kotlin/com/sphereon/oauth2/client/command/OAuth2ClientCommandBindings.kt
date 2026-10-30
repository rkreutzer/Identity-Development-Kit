/*
 * Copyright 2024-2026 Sphereon International B.V.
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

package com.sphereon.oauth2.client.command

import com.sphereon.core.api.service.SessionScopedCommandRegistry
import com.sphereon.di.session.SessionScope
import dev.zacsweers.metro.ContributesTo
import dev.zacsweers.metro.Provides

@ContributesTo(SessionScope::class)
interface OAuth2ClientCommandBindings {
    @Provides
    fun parseAuthorizationResponse(registry: SessionScopedCommandRegistry): ParseAuthorizationResponseCommand =
        registry.get(ParseAuthorizationResponseCommand.COMMAND_ID) as? ParseAuthorizationResponseCommand
            ?: error("No binding for ${ParseAuthorizationResponseCommand.COMMAND_ID}")

    @Provides
    fun createAuthorizationRequestUrl(registry: SessionScopedCommandRegistry): CreateAuthorizationRequestUrlCommand =
        registry.get(CreateAuthorizationRequestUrlCommand.COMMAND_ID) as? CreateAuthorizationRequestUrlCommand
            ?: error("No binding for ${CreateAuthorizationRequestUrlCommand.COMMAND_ID}")

    @Provides
    fun createSignedJar(registry: SessionScopedCommandRegistry): CreateSignedJarCommand =
        registry.get(CreateSignedJarCommand.COMMAND_ID) as? CreateSignedJarCommand
            ?: error("No binding for ${CreateSignedJarCommand.COMMAND_ID}")

    @Provides
    fun createEncryptedJar(registry: SessionScopedCommandRegistry): CreateEncryptedJarCommand =
        registry.get(CreateEncryptedJarCommand.COMMAND_ID) as? CreateEncryptedJarCommand
            ?: error("No binding for ${CreateEncryptedJarCommand.COMMAND_ID}")

    @Provides
    fun parseJar(registry: SessionScopedCommandRegistry): ParseJarCommand =
        registry.get(ParseJarCommand.COMMAND_ID) as? ParseJarCommand
            ?: error("No binding for ${ParseJarCommand.COMMAND_ID}")

    @Provides
    fun exchangeToken(registry: SessionScopedCommandRegistry): ExchangeTokenCommand =
        registry.get(ExchangeTokenCommand.COMMAND_ID) as? ExchangeTokenCommand
            ?: error("No binding for ${ExchangeTokenCommand.COMMAND_ID}")

    @Provides
    fun createPkce(registry: SessionScopedCommandRegistry): CreatePkceCommand =
        registry.get(CreatePkceCommand.COMMAND_ID) as? CreatePkceCommand
            ?: error("No binding for ${CreatePkceCommand.COMMAND_ID}")

    @Provides
    fun verifyPkce(registry: SessionScopedCommandRegistry): VerifyPkceCommand =
        registry.get(VerifyPkceCommand.COMMAND_ID) as? VerifyPkceCommand
            ?: error("No binding for ${VerifyPkceCommand.COMMAND_ID}")

    @Provides
    fun mergeRequestObject(registry: SessionScopedCommandRegistry): MergeRequestObjectCommand =
        registry.get(MergeRequestObjectCommand.COMMAND_ID) as? MergeRequestObjectCommand
            ?: error("No binding for ${MergeRequestObjectCommand.COMMAND_ID}")

    @Provides
    fun fetchAuthorizationServerMetadata(registry: SessionScopedCommandRegistry): FetchAuthorizationServerMetadataCommand =
        registry.get(FetchAuthorizationServerMetadataCommand.COMMAND_ID) as? FetchAuthorizationServerMetadataCommand
            ?: error("No binding for ${FetchAuthorizationServerMetadataCommand.COMMAND_ID}")

    @Provides
    fun fetchJwks(registry: SessionScopedCommandRegistry): FetchJwksCommand =
        registry.get(FetchJwksCommand.COMMAND_ID) as? FetchJwksCommand
            ?: error("No binding for ${FetchJwksCommand.COMMAND_ID}")

    @Provides
    fun fetchUserInfo(registry: SessionScopedCommandRegistry): FetchUserInfoCommand =
        registry.get(FetchUserInfoCommand.COMMAND_ID) as? FetchUserInfoCommand
            ?: error("No binding for ${FetchUserInfoCommand.COMMAND_ID}")

    @Provides
    fun completeOidcLogin(registry: SessionScopedCommandRegistry): CompleteOidcLoginCommand =
        registry.get(CompleteOidcLoginCommand.COMMAND_ID) as? CompleteOidcLoginCommand
            ?: error("No binding for ${CompleteOidcLoginCommand.COMMAND_ID}")

    @Provides
    fun privateKeyJwtClientAssertion(registry: SessionScopedCommandRegistry): PrivateKeyJwtClientAssertionServiceCommand =
        registry.get(PrivateKeyJwtClientAssertionServiceCommand.COMMAND_ID) as? PrivateKeyJwtClientAssertionServiceCommand
            ?: error("No binding for ${PrivateKeyJwtClientAssertionServiceCommand.COMMAND_ID}")

    @Provides
    fun startFederatedAuthentication(registry: SessionScopedCommandRegistry): StartFederatedAuthenticationCommand =
        registry.get(StartFederatedAuthenticationCommand.COMMAND_ID) as? StartFederatedAuthenticationCommand
            ?: error("No binding for ${StartFederatedAuthenticationCommand.COMMAND_ID}")

    @Provides
    fun completeFederatedAuthentication(registry: SessionScopedCommandRegistry): CompleteFederatedAuthenticationCommand =
        registry.get(CompleteFederatedAuthenticationCommand.COMMAND_ID) as? CompleteFederatedAuthenticationCommand
            ?: error("No binding for ${CompleteFederatedAuthenticationCommand.COMMAND_ID}")
}
