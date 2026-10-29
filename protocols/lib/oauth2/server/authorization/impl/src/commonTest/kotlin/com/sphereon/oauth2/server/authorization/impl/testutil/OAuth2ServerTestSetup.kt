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

package com.sphereon.oauth2.server.authorization.impl.testutil

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.context.ContextConfig
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.log.SessionLogService
import com.sphereon.core.api.service.TypedServiceCommandAdapter
import com.sphereon.core.api.session.CommandLifecycleInterceptorChain
import com.sphereon.core.api.session.asCoreApiServiceGraph
import com.sphereon.crypto.core.kms.KeyManagerService
import com.sphereon.crypto.core.kms.KmsProviderRegistry
import com.sphereon.crypto.core.kms.KmsProviderRegistryGraph
import com.sphereon.crypto.core.kms.asKeyManagerServiceGraph
import com.sphereon.crypto.kms.provider.software.SoftwareKmsProviderConfig
import com.sphereon.crypto.kms.provider.software.SoftwareKmsProviderFactoryImpl
import com.sphereon.crypto.core.KeyInfo
import com.sphereon.crypto.core.KeyType
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.crypto.resolution.managed.ManagedOptsKeyInfo
import com.sphereon.crypto.resolution.managed.MultiManagedIdentifierService
import com.sphereon.di.app.AppGraph
import com.sphereon.di.session.SessionContext
import com.sphereon.di.session.SessionContextManager
import com.sphereon.di.session.SessionInstance
import com.sphereon.oauth2.common.config.OAuth2ServerInstanceConfig
import com.sphereon.oauth2.common.config.MutableOAuth2ServerInstanceIdProvider
import com.sphereon.oauth2.common.config.OAuth2ServersConfig
import com.sphereon.oauth2.common.config.OAuth2ServersConfigProvider
import com.sphereon.oauth2.common.jarm.CreateJarmResponseArgs
import com.sphereon.oauth2.common.jarm.CreateJarmResponseCommand
import com.sphereon.oauth2.common.jarm.CreateJarmResponseResult
import com.sphereon.oauth2.common.jarm.JarmMode
import com.sphereon.oauth2.server.authorization.error.AuthorizationServerError
import com.sphereon.oauth2.server.authorization.impl.command.authorization.CreateAuthorizationErrorResponseCommandImpl
import com.sphereon.oauth2.server.authorization.impl.command.authorization.CreateAuthorizationResponseCommandImpl
import com.sphereon.oauth2.server.authorization.impl.command.discovery.BuildServerMetadataCommandImpl
import com.sphereon.oauth2.server.authorization.model.ClientRegistration
import com.sphereon.oauth2.server.authorization.signing.AsServerSigningIdentifierResolver
import com.sphereon.oauth2.server.authorization.signing.AsSigningRequirement
import com.sphereon.oauth2.server.authorization.signing.AsSigningSelection
import com.sphereon.oauth2.server.authorization.signing.CapturedAsServerConfig
import com.sphereon.oauth2.server.authorization.storage.ClientRegistry

expect fun createOAuth2ServerTestAppGraph(testInstance: Any): AppGraph

/**
 * Session-graph accessor for [MultiManagedIdentifierService]. Mirrors the existing
 * `asKeyManagerServiceGraph()` pattern in `lib-crypto-core` and lets discovery / id-token
 * tests resolve the configured signing key without re-implementing the KMS plumbing.
 */
fun Any.asMultiManagedIdentifierServiceGraph(): MultiManagedIdentifierService.Graph = this as MultiManagedIdentifierService.Graph

class OAuth2ServerTestContext(
    sessionId: String,
    testInstance: Any,
) {
    val app: AppGraph = createOAuth2ServerTestAppGraph(testInstance)
    val context = app.userContextManager.getAnonymous()
    val session: SessionInstance = context.sessionContextManager.createOrGetFromId(sessionId, principalType = com.sphereon.di.context.PrincipalType.USER)
    val execution = session.asCoreApiServiceGraph().serviceExecution
    val keyManagerService: KeyManagerService = session.graph.asKeyManagerServiceGraph().keyManagerService
    val identifierService: MultiManagedIdentifierService =
        session.graph.asMultiManagedIdentifierServiceGraph().multiManagedIdentifierService
    val kmsProviderRegistry: KmsProviderRegistry = (session.graph as KmsProviderRegistryGraph).kmsProviderRegistry

    init {
        // Register software KMS provider for crypto operations in tests
        val config = SoftwareKmsProviderConfig(id = "oauth2-test-software-kms")
        val factory = (app as SoftwareKmsProviderFactoryImpl.Graph).softwareKmsProvider
        val provider = factory.create(config, execution)
        keyManagerService.registerProvider(provider, makeDefaultKms = true)
    }
}

/**
 * Centralised constructor for [BuildServerMetadataCommandImpl] that all discovery tests share.
 * Wires a public RS256 descriptor for configured hosted OIDC/JWT discovery.
 * Signed-metadata generation remains explicitly stubbed in these tests.
 */
fun OAuth2ServerTestContext.newBuildServerMetadataCommand(configProvider: OAuth2ServersConfigProvider,): BuildServerMetadataCommandImpl =
    BuildServerMetadataCommandImpl(
        execution = this.execution,
        configProvider = configProvider,
        asInstanceIdProvider = fixedAsInstanceIdProvider(),
        signingIdentifierResolver = fixedSigningIdentifierResolver(
            ManagedOptsKeyInfo(
                identifier = KeyInfo<KeyType>(
                    alias = "discovery-rs256",
                    kid = "discovery-rs256",
                    signatureAlgorithm = SignatureAlgorithm.RSA_SHA256,
                ),
            ),
        ),
            grantHandlers = emptyMap(),
        kmsProviderRegistry = this.kmsProviderRegistry,
        // Discovery tests don't exercise signed_metadata; the stub returns Err so a
        // test that accidentally enables signed_metadata + serverIdentifier=null gets
        // a clear failure instead of silently producing an unsigned response.
        buildSignedMetadata = StubBuildSignedAuthorizationServerMetadataCommand(this.execution),
    )

/**
 * Wraps a fixed public descriptor (or null for no AS signing key) in an
 * [AsServerSigningIdentifierResolver], so command tests that construct the AS sign commands
 * directly can pin the resolved identifier without standing up a real SigningKeyStore.
 */
fun fixedSigningIdentifierResolver(identifier: ManagedOptsKeyInfo? = null,): AsServerSigningIdentifierResolver =
    object : AsServerSigningIdentifierResolver {
        override suspend fun selectSigning(
            captured: CapturedAsServerConfig,
            requirement: AsSigningRequirement,
            requestedAlgorithm: String?,
        ): AsSigningSelection {
            if (requirement == AsSigningRequirement.NOT_REQUIRED) return AsSigningSelection(null, emptySet())
            if (requirement == AsSigningRequirement.REQUIRED && identifier == null) error("No ACTIVE signing descriptor")
            val algorithm = identifier?.identifier?.signatureAlgorithm?.jose?.value
            val algorithms = algorithm?.let { setOf(it) } ?: emptySet()
            if (requestedAlgorithm != null && algorithm != requestedAlgorithm) {
                if (requirement == AsSigningRequirement.REQUIRED) error("Requested signing algorithm is unavailable")
                return AsSigningSelection(null, algorithms)
            }
            return AsSigningSelection(identifier, algorithms)
        }
    }

fun fixedAsInstanceIdProvider(key: String = "default"): MutableOAuth2ServerInstanceIdProvider =
    object : MutableOAuth2ServerInstanceIdProvider {
        private var selected: String? = key
        override fun currentAsInstanceId(): String? = selected
        override fun setCurrentAsInstanceId(asInstanceId: String) { selected = asInstanceId }
        override fun clearCurrentAsInstanceId() { selected = null }
    }

/**
 * Stub [com.sphereon.oauth2.server.authorization.command.BuildSignedAuthorizationServerMetadataCommand]
 * for command-level tests that exercise discovery without the signed_metadata feature.
 * Returns Err so a test that DOES enable signed_metadata sees a deterministic failure
 * (rather than getting a real signed JWT, which would couple discovery tests to JWS
 * cryptography). Tests that need a real signed-metadata round-trip wire the production
 * impl explicitly.
 */
class StubBuildSignedAuthorizationServerMetadataCommand(
    execution: SessionExecution,
) : TypedServiceCommandAdapter<
        com.sphereon.oauth2.server.authorization.command.BuildSignedAuthorizationServerMetadataArgs,
        com.sphereon.crypto.jose.jws.JwtCompactResult,
        IdkError,
    >(
        commandId = com.sphereon.oauth2.server.authorization.command.BuildSignedAuthorizationServerMetadataCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<com.sphereon.oauth2.server.authorization.command.BuildSignedAuthorizationServerMetadataArgs>(),
        outputTypeToken = typeToken<com.sphereon.crypto.jose.jws.JwtCompactResult>(),
    ),
    com.sphereon.oauth2.server.authorization.command.BuildSignedAuthorizationServerMetadataCommand {
    override val commandId: String = com.sphereon.oauth2.server.authorization.command.BuildSignedAuthorizationServerMetadataCommand.COMMAND_ID

    override suspend fun supports(args: Any): Boolean = args is com.sphereon.oauth2.server.authorization.command.BuildSignedAuthorizationServerMetadataArgs

    override suspend fun doExecute(
        args: com.sphereon.oauth2.server.authorization.command.BuildSignedAuthorizationServerMetadataArgs,
        applyDuring: (
            com.sphereon.oauth2.server.authorization.command.BuildSignedAuthorizationServerMetadataArgs
        ) -> com.sphereon.oauth2.server.authorization.command.BuildSignedAuthorizationServerMetadataArgs,
    ): IdkResult<com.sphereon.crypto.jose.jws.JwtCompactResult, IdkError> = Err(IdkError.fromString(code = "stub", message = "StubBuildSignedAuthorizationServerMetadataCommand never signs"))
}

/**
 * Stub [OAuth2ServersConfigProvider] for command-level tests that exercise the non-JARM paths
 * of the authorization-response commands. JARM is gated DISABLED so the JARM branches return
 * `invalid_request` if a test accidentally requests a `*.jwt` mode under this provider.
 */
class StubOAuth2ServersConfigProvider(
    private val config: OAuth2ServerInstanceConfig = OAuth2ServerInstanceConfig(),
) : OAuth2ServersConfigProvider {
    override val serverConfig: OAuth2ServerInstanceConfig get() = config

    override fun getConfig(): OAuth2ServersConfig = OAuth2ServersConfig(servers = mapOf("default" to config))

    override fun getServer(id: String): OAuth2ServerInstanceConfig? = if (id == "default") config else null

    override fun getDefaultServer(): OAuth2ServerInstanceConfig = config

    override fun resolveIssuer(
        serverId: String,
        tenantId: String,
    ): String = config.issuer ?: "https://stub.example.test"
}

/**
 * Stub [ClientRegistry] for command-level tests. Resolves whatever clients the test passes in,
 * defaulting to no clients. Mutation methods return `OperationNotSupported` so a test that
 * accidentally exercises them fails loudly.
 */
class StubClientRegistry(
    private val clients: Map<String, ClientRegistration> = emptyMap(),
) : ClientRegistry {
    override suspend fun getClient(clientId: String): IdkResult<ClientRegistration?, AuthorizationServerError.StorageError> = Ok(clients[clientId])

    override suspend fun registerClient(registration: ClientRegistration): IdkResult<ClientRegistration, AuthorizationServerError.StorageError> =
        Err(
            AuthorizationServerError.StorageError(
                operation = "registerClient",
                details = "StubClientRegistry is read-only",
            ),
        )

    override suspend fun updateClient(
        clientId: String,
        registration: ClientRegistration,
    ): IdkResult<ClientRegistration, AuthorizationServerError> =
        Err(
            AuthorizationServerError.StorageError(
                operation = "updateClient",
                details = "StubClientRegistry is read-only",
            ),
        )

    override suspend fun deleteClient(clientId: String): IdkResult<Unit, AuthorizationServerError> =
        Err(
            AuthorizationServerError.StorageError(
                operation = "deleteClient",
                details = "StubClientRegistry is read-only",
            ),
        )

    override suspend fun listClients(
        limit: Int,
        offset: Int,
    ): IdkResult<List<ClientRegistration>, AuthorizationServerError.StorageError> = Ok(clients.values.drop(offset).take(limit))

    override suspend fun findClientsByName(name: String): IdkResult<List<ClientRegistration>, AuthorizationServerError.StorageError> =
        Ok(clients.values.filter { it.clientName?.contains(name, ignoreCase = true) == true })

    override suspend fun clientExists(clientId: String): IdkResult<Boolean, AuthorizationServerError.StorageError> = Ok(clients.containsKey(clientId))

    override suspend fun verifyClientCredentials(
        clientId: String,
        clientSecret: String,
    ): IdkResult<Boolean, AuthorizationServerError.StorageError> {
        val client = clients[clientId] ?: return Ok(false)
        return Ok(client.clientSecret == clientSecret)
    }
}

/**
 * Stub [CreateJarmResponseCommand] that emits a deterministic `<jwt-stub>.<state>` fingerprint
 * so JARM-disabled paths can verify the command was never reached, while JARM tests can swap in
 * the real session-graph implementation when they actually want to exercise signing.
 */
class StubCreateJarmResponseCommand(
    execution: SessionExecution,
) : TypedServiceCommandAdapter<CreateJarmResponseArgs, CreateJarmResponseResult, IdkError>(
        commandId = CreateJarmResponseCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<CreateJarmResponseArgs>(),
        outputTypeToken = typeToken<CreateJarmResponseResult>(),
    ),
    CreateJarmResponseCommand {
    override val commandId: String = CreateJarmResponseCommand.COMMAND_ID

    override suspend fun supports(args: Any): Boolean = args is CreateJarmResponseArgs

    override suspend fun doExecute(
        args: CreateJarmResponseArgs,
        applyDuring: (CreateJarmResponseArgs) -> CreateJarmResponseArgs,
    ): IdkResult<CreateJarmResponseResult, IdkError> {
        val applied = applyDuring(args)
        return Ok(CreateJarmResponseResult(jarmJwt = "stub-jwt.${applied.state ?: ""}", mode = JarmMode.SIGNED))
    }
}

/**
 * Construct a [CreateAuthorizationResponseCommandImpl] for a non-JARM test path. JARM is gated
 * DISABLED through the stub config so the JARM branch never executes; the stub command and
 * registry are wired so DI argument count is satisfied.
 */
fun OAuth2ServerTestContext.newCreateAuthorizationResponseCommand(): CreateAuthorizationResponseCommandImpl =
    CreateAuthorizationResponseCommandImpl(
        execution = this.execution,
        configProvider = StubOAuth2ServersConfigProvider(),
        asInstanceIdProvider = fixedAsInstanceIdProvider(),
        clientRegistry = StubClientRegistry(),
        createJarmResponse = StubCreateJarmResponseCommand(this.execution),
        signingIdentifierResolver = fixedSigningIdentifierResolver(),
    )

/**
 * Mirrors [newCreateAuthorizationResponseCommand] for the error-response variant.
 */
fun OAuth2ServerTestContext.newCreateAuthorizationErrorResponseCommand(): CreateAuthorizationErrorResponseCommandImpl =
    CreateAuthorizationErrorResponseCommandImpl(
        execution = this.execution,
        configProvider = StubOAuth2ServersConfigProvider(),
        asInstanceIdProvider = fixedAsInstanceIdProvider(),
        clientRegistry = StubClientRegistry(),
        createJarmResponse = StubCreateJarmResponseCommand(this.execution),
        signingIdentifierResolver = fixedSigningIdentifierResolver(),
    )

/**
 * Test-only [SessionExecution] decorator that overrides [tenantId] with an explicit value.
 *
 * Delegates every other member to the wrapped real execution so the command under test
 * sees a fully functional session (real KMS, real command registry, real log service)
 * while the tenant resolves to whatever the test specifies. Mirrors the
 * [com.sphereon.oauth2.server.authorization.impl.command.admin.FailingGenerateKeyManagerService]
 * delegation pattern used in [RotateSigningKeyCommandImplTest].
 */
class TenantOverrideSessionExecution(
    private val delegate: SessionExecution,
    private val overrideTenantId: String,
) : SessionExecution by delegate {
    override val tenantId: String get() = overrideTenantId
    override val sessionContextManager: SessionContextManager get() = delegate.sessionContextManager
    override val sessionContext: SessionContext get() = delegate.sessionContext
    override val log: SessionLogService get() = delegate.log
    override val conf: ContextConfig get() = delegate.conf
    override val interceptorChain: CommandLifecycleInterceptorChain get() = delegate.interceptorChain
}
