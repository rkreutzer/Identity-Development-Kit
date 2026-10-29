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

package com.sphereon.oauth2.client.impl.command

import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.service.ServiceCommand
import com.sphereon.di.session.SessionScope
import com.sphereon.oauth2.client.command.CompleteFederatedAuthenticationCommand
import com.sphereon.oauth2.client.command.CompleteOidcLoginCommand
import com.sphereon.oauth2.client.command.StartFederatedAuthenticationCommand
import com.sphereon.oauth2.client.impl.federation.CompleteFederatedAuthenticationCommandImpl
import com.sphereon.oauth2.client.impl.federation.StartFederatedAuthenticationCommandImpl
import com.sphereon.oauth2.client.command.CreateAuthorizationRequestUrlCommand
import com.sphereon.oauth2.client.command.CreateEncryptedJarCommand
import com.sphereon.oauth2.client.command.CreatePkceCommand
import com.sphereon.oauth2.client.command.CreateSignedJarCommand
import com.sphereon.oauth2.client.command.ExchangeTokenCommand
import com.sphereon.oauth2.client.command.FetchAuthorizationServerMetadataCommand
import com.sphereon.oauth2.client.command.FetchJwksCommand
import com.sphereon.oauth2.client.command.FetchUserInfoCommand
import com.sphereon.oauth2.client.command.MergeRequestObjectCommand
import com.sphereon.oauth2.client.command.ParseAuthorizationResponseCommand
import com.sphereon.oauth2.client.command.ParseJarCommand
import com.sphereon.oauth2.client.command.PrivateKeyJwtClientAssertionServiceCommand
import com.sphereon.oauth2.client.command.VerifyPkceCommand
import com.sphereon.oauth2.client.impl.authorization.CreateAuthorizationRequestUrlCommandImpl
import com.sphereon.oauth2.client.impl.authorization.ParseAuthorizationResponseCommandImpl
import com.sphereon.oauth2.client.impl.clientauth.ApplyClientAuthenticationCommandImpl
import com.sphereon.oauth2.client.impl.clientauth.PrivateKeyJwtClientAssertionServiceCommandImpl
import com.sphereon.oauth2.client.impl.dpop.ClientVerifyDpopProofCommandImpl
import com.sphereon.oauth2.client.impl.dpop.CreateDpopProofCommandImpl
import com.sphereon.oauth2.client.impl.introspection.ClientIntrospectTokenCommandImpl
import com.sphereon.oauth2.client.impl.jar.CreateEncryptedJarCommandImpl
import com.sphereon.oauth2.client.impl.jar.CreateSignedJarCommandImpl
import com.sphereon.oauth2.client.impl.jar.MergeRequestObjectCommandImpl
import com.sphereon.oauth2.client.impl.jar.ParseJarCommandImpl
import com.sphereon.oauth2.client.impl.metadata.FetchAuthorizationServerMetadataCommandImpl
import com.sphereon.oauth2.client.impl.metadata.FetchJwksCommandImpl
import com.sphereon.oauth2.client.impl.oidc.CompleteOidcLoginCommandImpl
import com.sphereon.oauth2.client.impl.oidc.FetchUserInfoCommandImpl
import com.sphereon.oauth2.client.impl.pkce.CreatePkceCommandImpl
import com.sphereon.oauth2.client.impl.pkce.VerifyPkceCommandImpl
import com.sphereon.oauth2.client.impl.revocation.ClientRevokeTokenCommandImpl
import com.sphereon.oauth2.client.impl.token.ExchangeTokenCommandImpl
import com.sphereon.oauth2.common.command.ApplyClientAuthenticationCommand
import com.sphereon.oauth2.common.command.ClientRevokeTokenCommand
import com.sphereon.oauth2.common.command.CreateDpopProofCommand
import com.sphereon.oauth2.common.command.IntrospectTokenCommand
import com.sphereon.oauth2.common.command.VerifyDpopProofCommand
import dev.zacsweers.metro.ContributesTo
import dev.zacsweers.metro.IntoMap
import dev.zacsweers.metro.Provides
import dev.zacsweers.metro.StringKey

@ContributesTo(SessionScope::class)
interface OAuth2ClientCommandDescriptors {
    // PKCE commands
    @Provides @IntoMap
    @StringKey(VerifyPkceCommand.COMMAND_ID)
    fun verifyPkce(impl: VerifyPkceCommandImpl): ServiceCommand<*, *, *> = impl

    @Provides @IntoMap
    @StringKey(CreatePkceCommand.COMMAND_ID)
    fun createPkce(impl: CreatePkceCommandImpl): ServiceCommand<*, *, *> = impl

    // JAR commands
    @Provides @IntoMap
    @StringKey(CreateEncryptedJarCommand.COMMAND_ID)
    fun createEncryptedJar(impl: CreateEncryptedJarCommandImpl): ServiceCommand<*, *, *> = impl

    @Provides @IntoMap
    @StringKey(CreateSignedJarCommand.COMMAND_ID)
    fun createSignedJar(impl: CreateSignedJarCommandImpl): ServiceCommand<*, *, *> = impl

    @Provides @IntoMap
    @StringKey(MergeRequestObjectCommand.COMMAND_ID)
    fun mergeRequestObject(impl: MergeRequestObjectCommandImpl): ServiceCommand<*, *, *> = impl

    @Provides @IntoMap
    @StringKey(ParseJarCommand.COMMAND_ID)
    fun parseJar(impl: ParseJarCommandImpl): ServiceCommand<*, *, *> = impl

    // OpenID Federation Automatic Registration (Relying Party side)
    @Provides @IntoMap
    @StringKey(StartFederatedAuthenticationCommand.COMMAND_ID)
    fun startFederatedAuthentication(impl: StartFederatedAuthenticationCommandImpl): ServiceCommand<*, *, *> = impl

    @Provides @IntoMap
    @StringKey(CompleteFederatedAuthenticationCommand.COMMAND_ID)
    fun completeFederatedAuthentication(impl: CompleteFederatedAuthenticationCommandImpl): ServiceCommand<*, *, *> = impl

    // Authorization commands
    @Provides @IntoMap
    @StringKey(ParseAuthorizationResponseCommand.COMMAND_ID)
    fun parseAuthorizationResponse(impl: ParseAuthorizationResponseCommandImpl): ServiceCommand<*, *, *> = impl

    @Provides @IntoMap
    @StringKey(CreateAuthorizationRequestUrlCommand.COMMAND_ID)
    fun createAuthorizationRequestUrl(impl: CreateAuthorizationRequestUrlCommandImpl): ServiceCommand<*, *, *> = impl

    // Metadata commands
    @Provides @IntoMap
    @StringKey(FetchJwksCommand.COMMAND_ID)
    fun fetchJwks(impl: FetchJwksCommandImpl): ServiceCommand<*, *, *> = impl

    @Provides @IntoMap
    @StringKey(FetchAuthorizationServerMetadataCommand.COMMAND_ID)
    fun fetchAuthorizationServerMetadata(impl: FetchAuthorizationServerMetadataCommandImpl): ServiceCommand<*, *, *> = impl

    // Introspection commands
    @Provides @IntoMap
    @StringKey(IntrospectTokenCommand.COMMAND_ID)
    fun clientIntrospectToken(impl: ClientIntrospectTokenCommandImpl): ServiceCommand<*, *, *> = impl

    // Revocation commands
    @Provides @IntoMap
    @StringKey(ClientRevokeTokenCommand.COMMAND_ID)
    fun clientRevokeToken(impl: ClientRevokeTokenCommandImpl): ServiceCommand<*, *, *> = impl

    // Token commands
    @Provides @IntoMap
    @StringKey(ExchangeTokenCommand.COMMAND_ID)
    fun exchangeToken(impl: ExchangeTokenCommandImpl): ServiceCommand<*, *, *> = impl

    @Provides @IntoMap
    @StringKey(PrivateKeyJwtClientAssertionServiceCommand.COMMAND_ID)
    fun privateKeyJwtClientAssertion(impl: PrivateKeyJwtClientAssertionServiceCommandImpl): ServiceCommand<*, *, *> = impl

    // Client auth commands
    @Provides @IntoMap
    @StringKey(ApplyClientAuthenticationCommand.COMMAND_ID)
    fun applyClientAuthentication(impl: ApplyClientAuthenticationCommandImpl): ServiceCommand<*, *, *> = impl

    // DPoP commands
    @Provides @IntoMap
    @StringKey(CreateDpopProofCommand.COMMAND_ID)
    fun createDpopProof(impl: CreateDpopProofCommandImpl): ServiceCommand<*, *, *> = impl

    @Provides @IntoMap
    @StringKey(VerifyDpopProofCommand.COMMAND_ID)
    fun clientVerifyDpopProof(impl: ClientVerifyDpopProofCommandImpl): ServiceCommand<*, *, *> = impl

    // OIDC commands
    @Provides @IntoMap
    @StringKey(FetchUserInfoCommand.COMMAND_ID)
    fun fetchUserInfo(impl: FetchUserInfoCommandImpl): ServiceCommand<*, *, *> = impl

    @Provides @IntoMap
    @StringKey(CompleteOidcLoginCommand.COMMAND_ID)
    fun completeOidcLogin(impl: CompleteOidcLoginCommandImpl): ServiceCommand<*, *, *> = impl
}

