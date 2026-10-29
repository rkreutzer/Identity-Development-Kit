package com.sphereon.openid.oid4vci.integration

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.conf.DefaultAppMapPropertySource
import com.sphereon.core.api.conf.DefaultPrincipalMapPropertySource
import com.sphereon.core.api.conf.DefaultTenantMapPropertySource
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.session.asCoreApiServiceGraph
import com.sphereon.crypto.core.KeyInfo
import com.sphereon.crypto.core.KeyType
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.crypto.core.kms.asKeyManagerServiceGraph
import com.sphereon.crypto.kms.provider.software.SoftwareKmsProviderConfig
import com.sphereon.crypto.kms.provider.software.SoftwareKmsProviderFactoryImpl
import com.sphereon.di.app.AppGraph
import com.sphereon.di.context.MutableResolvedTenantIdProvider
import com.sphereon.di.session.SessionInstance
import com.sphereon.di.session.SessionScope
import com.sphereon.oauth2.common.config.MutableOAuth2ServerInstanceIdProvider
import com.sphereon.oauth2.common.model.ClientAuthenticationConfig
import com.sphereon.oauth2.common.model.ClientAuthenticationMethod
import com.sphereon.oauth2.common.model.GrantType
import com.sphereon.oauth2.server.authorization.model.ClientRegistration
import com.sphereon.oauth2.server.authorization.model.ClientType
import com.sphereon.oauth2.server.authorization.storage.ClientRegistry
import com.sphereon.oauth2.server.authorization.storage.OAuth2SigningKey
import com.sphereon.oauth2.server.authorization.storage.OAuth2SigningKeyState
import com.sphereon.oauth2.server.authorization.storage.SigningKeyStore
import com.sphereon.openid.oid4vci.issuer.config.MutableOid4vciIssuerInstanceIdProvider
import com.sphereon.openid.oid4vci.issuer.config.Oid4vciIssuerProtocolConfig
import com.sphereon.wallet.interaction.protocol.oid4vci.Oid4vciTokenEndpointProofRequest
import com.sphereon.wallet.interaction.protocol.oid4vci.Oid4vciTokenEndpointProofs
import com.sphereon.wallet.interaction.protocol.oid4vci.Oid4vciTokenEndpointProofsProvider
import dev.zacsweers.metro.AppScope
import dev.zacsweers.metro.ContributesTo
import kotlin.time.Clock

const val OID4VCI_TEST_ISSUER_URL = "https://issuer.example.com"
const val OID4VCI_TEST_AS_SIGNING_KEY_ALIAS = "oauth2-server-signing"
const val OID4VCI_TEST_TENANT_ID = "default"
const val OID4VCI_TEST_ISSUER_INSTANCE_ID = "00000000-0000-4000-8000-000000000001"

class Oid4vciTestContext(
    testInstance: Any,
    protocolBasePath: String = "",
    credentialConfigurationIds: List<String> = listOf("UniversityDegree"),
) {
    init {
        // The OID4VCI integration tests run a single hosted AS that issues access tokens for
        // the credential endpoint. The AS's `OAuth2ServersConfigBinder` reads these properties
        // at session-start time, so they have to be in place before the AppGraph touches its
        // session graph. Without them, `CreateAccessTokenCommand` fails with "OAuth2 server has
        // no issuer configured".
        DefaultPrincipalMapPropertySource.addProperty(
            "${com.sphereon.oauth2.common.config.OAuth2ServerInstanceConfig.CONFIG_PREFIX}.default.issuer",
            OID4VCI_TEST_ISSUER_URL,
        )
        DefaultPrincipalMapPropertySource.addProperty(
            "${com.sphereon.oauth2.common.config.OAuth2ServerInstanceConfig.CONFIG_PREFIX}.default.mode",
            "HOSTED",
        )
        DefaultPrincipalMapPropertySource.addProperty(
            "${com.sphereon.oauth2.common.config.OAuth2ServerInstanceConfig.CONFIG_PREFIX}.default.grant-types-enabled",
            "authorization_code,client_credentials,refresh_token,urn:ietf:params:oauth:grant-type:pre-authorized_code",
        )
        configureOid4vciTestInternalClient()
        // The real registry-backed issuer requires an explicitly owned resource namespace.
        val issuerRoot = "oid4vci.issuers.$OID4VCI_TEST_ISSUER_INSTANCE_ID"
        val authorizationServerId = "00000000-0000-4000-8000-000000000002"
        val authorizationServerRoot = "$issuerRoot.authorizationServers.$authorizationServerId"
        val issuerProperties =
            mapOf(
                "oid4vci.routing.issuerResourceId" to OID4VCI_TEST_ISSUER_INSTANCE_ID,
                "$issuerRoot.identifier" to OID4VCI_TEST_ISSUER_URL,
                "$issuerRoot.credentialConfigurationIds" to credentialConfigurationIds.joinToString(","),
                "$issuerRoot.issuerCapabilityId" to "00000000-0000-4000-8000-000000000003",
                "$issuerRoot.authorizationServerIds" to authorizationServerId,
                "$issuerRoot.profile" to "OID4VCI_1_0_FINAL",
                "$issuerRoot.profileRevision" to "7",
                "$authorizationServerRoot.tenantId" to OID4VCI_TEST_TENANT_ID,
                "$authorizationServerRoot.issuerIdentifier" to OID4VCI_TEST_ISSUER_URL,
                "$authorizationServerRoot.enabled" to "true",
                "$authorizationServerRoot.default" to "true",
                "$authorizationServerRoot.lifecycle" to "ACTIVE",
                "$authorizationServerRoot.deployment" to "HOSTED",
                "$authorizationServerRoot.credentialIssuancePurpose" to "true",
                "$authorizationServerRoot.allowedGrants" to "PRE_AUTHORIZED_CODE",
                "$authorizationServerRoot.revision" to "11",
                "$authorizationServerRoot.runtimeServerKey" to "default",
                "$authorizationServerRoot.jwksUri" to "$OID4VCI_TEST_ISSUER_URL/.well-known/jwks.json",
                "$authorizationServerRoot.tokenEndpoint" to "$OID4VCI_TEST_ISSUER_URL/token",
                "$authorizationServerRoot.discoveryCurrent" to "true",
                "$authorizationServerRoot.bindingRevision" to "13",
                "$issuerRoot.credentials.[UniversityDegree].format" to "jwt_vc_json",
                "$issuerRoot.credentials.[UniversityDegree].scope" to "degree",
                "$issuerRoot.credentials.[UniversityDegree].bindingMethods" to "did:key,did:jwk,jwk",
                "$issuerRoot.credentials.[UniversityDegree].signingAlgorithms" to "ES256",
                "$issuerRoot.credentials.[UniversityDegree].proofTypes.jwt.signingAlgorithms" to "ES256",
                "$issuerRoot.credentials.[UniversityDegree].signingKeyMode" to "jwk-thumbprint",
                "$issuerRoot.credentials.[UniversityDegree].credentialDefinition.types" to "VerifiableCredential,UniversityDegreeCredential",
            )
        issuerProperties.forEach { (key, value) -> DefaultPrincipalMapPropertySource.addProperty(key, value) }
        // Credential requests execute against the app-scoped configuration. Keep the integration
        // issuer explicit about its ordinary business-authorization decision; production remains
        // fail-closed when this policy is not configured.
        DefaultAppMapPropertySource.addProperty(
            "oid4vci.business-authorization.mode",
            "ordinary",
        )
        DefaultAppMapPropertySource.addProperty(
            Oid4vciIssuerProtocolConfig.BASE_PATH_KEY,
            Oid4vciIssuerProtocolConfig.normalizeBasePath(protocolBasePath),
        )
    }

    val app: AppGraph = createOid4vciTestAppGraph(application = testInstance)
    val context =
        app.userContextManager.createOrGet(
            tenantAware =
                object : com.sphereon.di.context.TenantAware {
                    override val tenant =
                        object : com.sphereon.di.context.TenantContextData {
                            override val tenantId = OID4VCI_TEST_TENANT_ID
                        }
                },
            principalAware =
                object : com.sphereon.di.context.PrincipalAware {
                    override val principal = "oid4vci-integration-test-user"
                },
            principalType = com.sphereon.di.context.PrincipalType.USER,
            makeActive = false,
        )
    val session: SessionInstance = context.sessionContextManager.createOrGetFromId("oid4vci-e2e-test", principalType = com.sphereon.di.context.PrincipalType.USER)
    val execution = session.asCoreApiServiceGraph().serviceExecution
    val signingKeyStore: SigningKeyStore = (app as Oid4vciSigningKeyStoreGraph).signingKeyStore

    init {
        (session.graph as Oid4vciTenantOverrideSessionGraph).mutableResolvedTenantIdProvider.setCurrentTenantId(OID4VCI_TEST_TENANT_ID)
        // Direct internal command calls use the fixture's explicitly configured hosted AS.
        (session.graph as Oid4vciTenantOverrideSessionGraph).mutableOAuth2ServerInstanceIdProvider.setCurrentAsInstanceId("default")
        (session.graph as Oid4vciIssuerInstanceOverrideSessionGraph)
            .mutableOid4vciIssuerInstanceIdProvider
            .setCurrentInstanceId(OID4VCI_TEST_ISSUER_INSTANCE_ID)

        // Register software KMS provider for crypto operations in tests
        val config = SoftwareKmsProviderConfig(id = "oid4vci-test-kms")
        val factory = (app as SoftwareKmsProviderFactoryImpl.Graph).softwareKmsProvider
        val provider = factory.create(config, execution)
        val kms = session.graph.asKeyManagerServiceGraph().keyManagerService
        kms.registerProvider(provider, makeDefaultKms = true)
    }

    /**
     * Generate the AS signing key in KMS and register it with the [SigningKeyStore] so the
     * AS sign paths (`CreateAccessTokenCommand`, `CreateIdTokenCommand`) and `GetJwksCommand`
     * resolve the same active key. Returns the alias.
     */
    suspend fun ensureAsSigningKey(
        alias: String = OID4VCI_TEST_AS_SIGNING_KEY_ALIAS,
        alg: SignatureAlgorithm = SignatureAlgorithm.ECDSA_SHA256,
        tenantId: String = OID4VCI_TEST_TENANT_ID,
    ): String {
        val kms = session.graph.asKeyManagerServiceGraph().keyManagerService
        val gen =
            kms.generateKeyResult(
                alias = alias,
                use = com.sphereon.crypto.core.jose.JwkUse.sig,
                alg = alg,
            )
        check(gen.isOk) { "AS signing key generation failed: ${if (gen.isErr) gen.error.message.defaultMessage else "<unknown>"}" }
        val keyPair = checkNotNull(gen.value.keyPair) { "generateKeyResult succeeded but keyPair is null" }
        val now = Clock.System.now()
        val signingKey =
            OAuth2SigningKey(
                tenantId = tenantId,
                keyInfo =
                    KeyInfo<KeyType>(
                        kid = keyPair.kid ?: keyPair.alias,
                        alias = alias,
                        providerId = keyPair.providerId,
                        signatureAlgorithm = alg,
                    ),
                state = OAuth2SigningKeyState.ACTIVE,
                priority = 1,
                createdAt = now,
                notBefore = now,
            )
        val register = signingKeyStore.register(signingKey)
        check(register.isOk) { "Failed to register AS signing key: ${if (register.isErr) register.error else "<unknown>"}" }
        return alias
    }

    /** Admit the identified public wallet used by the real pre-authorized-code token exchange. */
    suspend fun ensurePublicWalletClient(clientId: String) =
        withAuthorizationServer {
            val registry = (session.graph as Oid4vciTenantOverrideSessionGraph).clientRegistry
            val existing = registry.getClient(clientId).getOrThrow()
            if (existing == null) {
                val registered =
                    registry.registerClient(
                        ClientRegistration(
                            clientId = clientId,
                            clientType = ClientType.PUBLIC,
                            grantTypes = listOf(GrantType.PRE_AUTHORIZED_CODE),
                            tokenEndpointAuthMethod = ClientAuthenticationMethod.NONE,
                        ),
                    )
                check(registered.isOk) { "Public wallet registration must succeed" }
            } else {
                check(existing.clientType == ClientType.PUBLIC && existing.tokenEndpointAuthMethod == ClientAuthenticationMethod.NONE) {
                    "The fixture wallet must remain an explicitly registered public client"
                }
            }
        }

    /** Restore the fixture's trusted AS selection after an HTTP adapter has cleared request state. */
    suspend fun <T> withAuthorizationServer(block: suspend () -> T): T {
        val selection = (session.graph as Oid4vciTenantOverrideSessionGraph).mutableOAuth2ServerInstanceIdProvider
        val previous = selection.currentAsInstanceId()
        selection.setCurrentAsInstanceId("default")
        return try {
            block()
        } finally {
            if (previous == null) {
                selection.clearCurrentAsInstanceId()
            } else {
                selection.setCurrentAsInstanceId(previous)
            }
        }
    }

    suspend fun registerIssuerSigningKey(
        keyName: String,
        issuerInstanceId: String = OID4VCI_TEST_ISSUER_INSTANCE_ID,
        tenantId: String = OID4VCI_TEST_TENANT_ID,
    ) {
        (app as Oid4vciTestIssuerKeyNameRegistryGraph)
            .oid4vciTestIssuerKeyNameRegistry
            .register(
                tenantId = tenantId,
                issuerInstanceId = issuerInstanceId,
                keyName = keyName,
            )
    }
}

/**
 * Graph extension exposing the AppScope-bound [SigningKeyStore] to the integration test
 * fixtures so they can register a signing key before AS sign paths run.
 */
@ContributesTo(AppScope::class)
interface Oid4vciSigningKeyStoreGraph {
    val signingKeyStore: SigningKeyStore
}

/** Exposes the explicit E2E key-name authority so fixtures can register keys they generated. */
@ContributesTo(AppScope::class)
interface Oid4vciTestIssuerKeyNameRegistryGraph {
    val oid4vciTestIssuerKeyNameRegistry: Oid4vciTestIssuerKeyNameRegistry
}

@ContributesTo(SessionScope::class)
interface Oid4vciTenantOverrideSessionGraph {
    val mutableResolvedTenantIdProvider: MutableResolvedTenantIdProvider
    val mutableOAuth2ServerInstanceIdProvider: MutableOAuth2ServerInstanceIdProvider
    val clientRegistry: ClientRegistry
}

@ContributesTo(SessionScope::class)
interface Oid4vciIssuerInstanceOverrideSessionGraph {
    val mutableOid4vciIssuerInstanceIdProvider: MutableOid4vciIssuerInstanceIdProvider
}

/** Match the credential-proof issuer to the client identity sent in the real token request. */
fun integrationPublicWalletTokenEndpointProofs(clientId: String): Oid4vciTokenEndpointProofsProvider =
    object : Oid4vciTokenEndpointProofsProvider {
        override suspend fun proofs(request: Oid4vciTokenEndpointProofRequest): IdkResult<Oid4vciTokenEndpointProofs, IdkError> {
            check(request.options.clientId == clientId) { "Token and credential proof client identities must match" }
            return Ok(Oid4vciTokenEndpointProofs(clientAuthentication = ClientAuthenticationConfig.None(clientId)))
        }
    }

/** Opaque internal clients belong to the tenant configuration, never to a caller principal. */
internal fun configureOid4vciTestInternalClient() {
    val root = "oauth2.servers.default.internal-clients.issuer"
    mapOf(
        "$root.client-id" to "issuer-service",
        "$root.client-secret" to "issuer-secret",
        "$root.default-access-token-audience" to OID4VCI_TEST_ISSUER_URL,
        "$root.allowed-access-token-audiences" to OID4VCI_TEST_ISSUER_URL,
    ).forEach { (key, value) -> DefaultTenantMapPropertySource.addProperty(key, value) }
}
