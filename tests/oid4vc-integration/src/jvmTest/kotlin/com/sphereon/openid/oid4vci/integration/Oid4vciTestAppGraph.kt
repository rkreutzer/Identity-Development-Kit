package com.sphereon.openid.oid4vci.integration

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.conf.DefaultPrincipalMapPropertySource
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.defaults.app.DefaultRootScopeProvider
import com.sphereon.data.store.party.model.IdentityRole
import com.sphereon.di.app.AbstractAppGraph
import com.sphereon.di.app.RootScopeProvider
import com.sphereon.di.session.SessionScope
import com.sphereon.oauth2.jwt.validation.JwtValidationConfig
import com.sphereon.openid.oid4vci.issuer.impl.http.HttpAsBridge
import com.sphereon.openid.oid4vci.issuer.spi.IssuerKeyNameResolver
import com.sphereon.wallet.WalletIdentityResolver
import com.sphereon.wallet.credential.IdentifierRef
import com.sphereon.wallet.interaction.WalletAttendedAuthorizationRegistry
import com.sphereon.wallet.interaction.WalletCounterpartyEncounterRegistry
import com.sphereon.wallet.interaction.WalletInteractionClient
import com.sphereon.wallet.interaction.WalletInteractionDiagnostics
import com.sphereon.wallet.interaction.WalletInteractionPrivateSessionStore
import com.sphereon.wallet.interaction.WalletInteractionSensitiveInputAuthority
import com.sphereon.wallet.interaction.impl.DefaultWalletInteractionEngine
import com.sphereon.wallet.interaction.impl.InMemoryWalletInteractionPrivateSessionStore
import com.sphereon.wallet.interaction.impl.InMemoryWalletInteractionSessionStore
import com.sphereon.wallet.interaction.impl.LocalWalletInteractionClient
import com.sphereon.wallet.interaction.impl.StoreBackedWalletInteractionSensitiveInputAuthority
import com.sphereon.wallet.interaction.impl.WalletInteractionSessionStore
import com.sphereon.wallet.wsca.impl.UnavailableWalletUserAuthenticator
import com.sphereon.wallet.wsca.impl.WalletUserAuthenticator
import com.sphereon.wallet.wscd.ActivationProof
import com.sphereon.wallet.wscd.ActivationProofKind
import com.sphereon.wallet.wscd.SoftwareWscdKeyStoreConfiguration
import com.sphereon.wallet.wscd.testfixtures.WalletAppGraphInteractionBindings
import dev.zacsweers.metro.AppScope
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.ContributesIntoSet
import dev.zacsweers.metro.ContributesTo
import dev.zacsweers.metro.DependencyGraph
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.Named
import dev.zacsweers.metro.Provides
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding
import dev.zacsweers.metro.createGraphFactory
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

// This in-process fixture uses the existing Sphereon bridge contribution through its public SPI.
@DependencyGraph(AppScope::class, excludes = [HttpAsBridge::class])
abstract class Oid4vciTestAppGraph : AbstractAppGraph() {
    @Provides
    @SingleIn(AppScope::class)
    fun provideJwtValidationConfig(): JwtValidationConfig = JwtValidationConfig()

    // The software WSCD requires an explicit key-custody policy (product roots fail closed on
    // PersistentStorageRequired); these in-process protocol tests are ephemeral by design.
    @Provides
    @SingleIn(AppScope::class)
    fun provideSoftwareWscdKeyStoreConfiguration(): SoftwareWscdKeyStoreConfiguration = SoftwareWscdKeyStoreConfiguration.InMemoryForTestingOnly

    @DependencyGraph.Factory
    fun interface Factory {
        fun create(
            @Provides application: Any,
            @Provides @Named("appId") appId: String,
            @Provides @Named("profile") profile: String,
            @Provides @Named("version") version: String,
            @Provides rootScopeProvider: RootScopeProvider,
        ): Oid4vciTestAppGraph
    }
}

/**
 * Explicit in-process authority for issuer signing-key names.
 *
 * Production resolves these names from a tenant and issuer resource handle. The E2E fixture has no
 * enterprise resource authority, so it registers only the test key it created for a specific
 * tenant/issuer pair. It deliberately never reads protocol configuration aliases.
 */
interface Oid4vciTestIssuerKeyNameRegistry {
    suspend fun register(
        tenantId: String,
        issuerInstanceId: String,
        keyName: String,
    )

    suspend fun resolve(
        tenantId: String,
        issuerInstanceId: String,
    ): String?
}

@Inject
@SingleIn(AppScope::class)
@ContributesBinding(AppScope::class, binding = binding<Oid4vciTestIssuerKeyNameRegistry>())
class InMemoryOid4vciTestIssuerKeyNameRegistry : Oid4vciTestIssuerKeyNameRegistry {
    private val mutex = Mutex()
    private val keyNames = mutableMapOf<Pair<String, String>, String>()

    override suspend fun register(
        tenantId: String,
        issuerInstanceId: String,
        keyName: String,
    ) {
        mutex.withLock {
            keyNames[tenantId to issuerInstanceId] = keyName
        }
    }

    override suspend fun resolve(
        tenantId: String,
        issuerInstanceId: String,
    ): String? =
        mutex.withLock {
            keyNames[tenantId to issuerInstanceId]
        }
}

/**
 * E2E-only replacement for the enterprise typed-handle resolver.
 *
 * It has the same tenant/issuer lookup contract, backed by the explicit test authority above.
 * An unregistered pair refuses exactly as production does.
 */
@Inject
@SingleIn(SessionScope::class)
@ContributesBinding(
    SessionScope::class,
    binding = binding<IssuerKeyNameResolver>(),
)
class Oid4vciTestIssuerKeyNameResolver(
    private val registry: Oid4vciTestIssuerKeyNameRegistry,
) : IssuerKeyNameResolver {
    override suspend fun resolveMetadataSigningKeyName(
        tenantId: String,
        issuerInstanceId: String,
    ): String? = registry.resolve(tenantId, issuerInstanceId)

    override suspend fun resolveRequestDecryptionKeyName(
        tenantId: String,
        issuerInstanceId: String,
    ): String? = null
}

@ContributesTo(SessionScope::class, replaces = [WalletAppGraphInteractionBindings::class])
interface Oid4vciWalletInteractionTestModule {
    @Provides
    @SingleIn(SessionScope::class)
    fun provideWalletAttendedAuthorizationRegistry(): WalletAttendedAuthorizationRegistry = WalletAttendedAuthorizationRegistry.none

    @Provides
    @SingleIn(SessionScope::class)
    fun provideWalletInteractionPrivateSessionStore(): WalletInteractionPrivateSessionStore = InMemoryWalletInteractionPrivateSessionStore()

    @Provides
    @SingleIn(SessionScope::class)
    fun provideWalletInteractionSensitiveInputAuthority(store: WalletInteractionPrivateSessionStore,): WalletInteractionSensitiveInputAuthority =
        StoreBackedWalletInteractionSensitiveInputAuthority(store)

    @Provides
    @SingleIn(SessionScope::class)
    fun provideWalletInteractionSessionStore(): WalletInteractionSessionStore = InMemoryWalletInteractionSessionStore()

    @Provides
    @SingleIn(SessionScope::class)
    fun provideWalletCounterpartyEncounterRegistry(): WalletCounterpartyEncounterRegistry = WalletCounterpartyEncounterRegistry.none

    @Provides
    @SingleIn(SessionScope::class)
    fun provideWalletInteractionEngine(
        privateSessionStore: WalletInteractionPrivateSessionStore,
        sessionStore: WalletInteractionSessionStore,
        sensitiveInputAuthority: WalletInteractionSensitiveInputAuthority,
    ): DefaultWalletInteractionEngine =
        DefaultWalletInteractionEngine(
            sensitiveInputAuthority = sensitiveInputAuthority,
            privateSessionStore = privateSessionStore,
            sessionStore = sessionStore,
            launchAuthorities = setOf(integrationOrdinaryLaunchAuthority()),
            diagnostics = WalletInteractionDiagnostics.none,
        )

    @Provides
    @SingleIn(SessionScope::class)
    fun provideWalletInteractionClient(engine: DefaultWalletInteractionEngine): WalletInteractionClient = LocalWalletInteractionClient(engine)
}

/** Promptless attended-operation authorization for in-process protocol tests only. */
@Inject
@SingleIn(SessionScope::class)
@ContributesBinding(
    SessionScope::class,
    binding = binding<WalletUserAuthenticator>(),
    replaces = [UnavailableWalletUserAuthenticator::class],
)
class Oid4vciTestWalletUserAuthenticator : WalletUserAuthenticator {
    override suspend fun authenticate(request: com.sphereon.wallet.wsca.WscaUserAuthRequest) =
        Ok(
            ActivationProof(
                kind = ActivationProofKind.LOCAL_USER_AUTH,
                token = "oid4vci-integration-attended-operation",
                digestBinding = request.digestBinding,
                nonce = request.nonce,
                evidence = mapOf("factor" to "pin"),
            ),
        )
}

/** Test-only identity authority for protocol fixtures that intentionally do not persist Party data. */
@Inject
@SingleIn(SessionScope::class)
@ContributesBinding(SessionScope::class, binding = binding<WalletIdentityResolver>())
@ContributesIntoSet(SessionScope::class)
class Oid4vciTestWalletIdentityResolver : WalletIdentityResolver {
    override suspend fun resolve(
        ref: IdentifierRef,
        role: IdentityRole,
    ): IdkResult<IdentifierRef, IdkError> = Ok(ref)
}

fun createOid4vciTestAppGraph(
    application: Any = "Oid4vciIntegrationTest",
    appId: String = "com.sphereon.oid4vci.integration.test",
    profile: String = "test",
    version: String = "test",
): Oid4vciTestAppGraph {
    // Software WSCD rehydration deliberately fails closed without authoritative wallet-unit
    // ownership metadata.  The integration graph uses the shared in-memory test authority so
    // generated holder keys remain verifiable across the WSCA/WSCD boundary without weakening
    // the production ownership check.
    DefaultPrincipalMapPropertySource.addProperty("database.app.dialect", "in-memory-test")
    val graph =
        createGraphFactory<Oid4vciTestAppGraph.Factory>().create(
            application = application,
            appId = appId,
            profile = profile,
            version = version,
            rootScopeProvider = DefaultRootScopeProvider(),
        )
    graph.initRootScopeProvider()
    return graph
}
