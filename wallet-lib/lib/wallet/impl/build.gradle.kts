import com.sphereon.gradle.plugin.configureStandardTargets

plugins {
    `maven-publish`
    alias(sphereonplug.plugins.org.jetbrains.kotlin.multiplatform)
    alias(sphereonplug.plugins.com.vanniktech.maven.publish)
    alias(sphereonplug.plugins.org.jetbrains.kotlin.plugin.serialization)
    alias(sphereonplug.plugins.com.sphereon.gradle.plugin.npm.publication)
    alias(sphereonplug.plugins.dev.zacsweers.metro)
}
metro {
}

kotlin {
    configureStandardTargets()

    sourceSets {
        val commonMain by getting {
            dependencies {
                api(projects.libWalletPublic)
                api(projects.libWalletWscaPublic)
                // LocalWsca (Wsca policy implementation): impl reaches it via this
                // dependency so its @ContributesBinding merges into the session graph, exactly like the
                // lib-wallet-wscd-software dependency below does for the Wscd/WscdFactory bindings.
                api(projects.libWalletWscaImpl)
                // Software WSCD implementation (SoftwareWscd, SoftwareWscdWalletCredentialBodyProtector,
                // SoftwareWscdBootstrap) lives in its own module; impl reaches it via this dependency.
                api(projects.libWalletWscdSoftware)
                api(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-data-store-blob-public:$version" else project(":lib-data-store-blob-public"))
                api(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-data-store-blob-impl:$version" else project(":lib-data-store-blob-impl"))
                api(libs.bundles.app.platform.di)
                api(sphereonlib.software.amazon.app.platform.metro.public)
                implementation(sphereonlib.software.amazon.app.platform.metro.impl)
                api(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-openid-oid4vci-holder-impl:$version" else project(":lib-openid-oid4vci-holder-impl"))
                api(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-openid-oid4vp-holder-impl:$version" else project(":lib-openid-oid4vp-holder-impl"))
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-mdoc-core-impl:$version" else project(":lib-mdoc-core-impl"))
                // SD-JWT VC verification command (sdjwt.vc.verify): the wallet verifies the
                // issuer signature of an issued SD-JWT VC on receipt before storing it.
                api(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-sdjwt-public:$version" else project(":lib-sdjwt-public"))
                // Deliberately NO direct api(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-core-impl:$version" else project(":lib-crypto-core-impl")) edge: no source in this
                // module imports com.sphereon.crypto.core.impl.*
                // directly; lib-crypto-core-impl's non-KMS JOSE/crypto command impls (JwtServiceImpl,
                // JweServiceImpl, DefaultSignatureService, X509VerifyServiceImpl, CryptoServicesImpl)
                // remain compile-visible transitively via libOpenidOid4vciHolderImpl's OWN
                // api(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-core-impl:$version" else project(":lib-crypto-core-impl")) dependency (libOpenidOid4vciHolderImpl is itself an
                // api dependency of this module, so the api chain to lib-crypto-core-impl is
                // unbroken).
                api(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-oauth2-client-impl:$version" else project(":lib-oauth2-client-impl"))
                api(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-data-link-http-client-public:$version" else project(":lib-data-link-http-client-public"))
            }
        }
        val commonTest by getting {
            dependencies {
                implementation(kotlin("test"))
                implementation(sphereonlib.org.jetbrains.kotlinx.coroutines.test)
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-data-store-blob-impl-memory:$version" else project(":lib-data-store-blob-impl-memory"))
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-data-store-kv-impl-memory:$version" else project(":lib-data-store-kv-impl-memory"))
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-core-events-impl:$version" else project(":lib-core-events-impl"))
                // defaultSecureRandom() for the LocalWsca(SoftwareWscd(...), DpopProofAssembly(...))
                // wiring the fake-KMS-backed tests construct directly.
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-core-api-default:$version" else project(":lib-core-api-default"))
            }
        }
        val jvmMain by getting {
            dependencies {
                // DefaultRootScopeProvider + DefaultPrincipalMapPropertySource for WalletAppGraph
                api(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-core-api-default:$version" else project(":lib-core-api-default"))
                // Deliberately NO api(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-kms-provider-software:$version" else project(":lib-crypto-kms-provider-software")) edge: software KMS
                // provider registration lives behind the WSCA/WSCD boundary
                // (SoftwareKmsProviderRegistrar, lib-wallet-wscd-software), which this module already
                // depends on via libWalletWscdSoftware, so no source here needs the KMS provider
                // module directly. libWalletWscdSoftware's OWN dependency on the KMS provider module
                // is `implementation` (provider types must not leak onto consumers' compile
                // classpath), so it does not re-expose it transitively either. If :lib-wallet-impl
                // fails to compile/wire with a "no binding for SoftwareKmsProviderFactory" error,
                // add `implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-kms-provider-software:$version" else project(":lib-crypto-kms-provider-software"))` here (not `api` -
                // nothing else needs it re-exposed).
                // Event service bindings needed by the App/User/Session graph
                api(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-core-events-impl:$version" else project(":lib-core-events-impl"))
                // HTTP client factory + URI command bindings needed by OID4VCI/OID4VP holder impls
                api(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-data-link-http-client-impl:$version" else project(":lib-data-link-http-client-impl"))
                // OAuth2 common impl (CreateJarmResponseCommandImpl, VerifyJarmResponseCommandImpl):
                // pulled in transitively at runtime via libOauth2ClientImpl but NOT on compile
                // classpath; Metro @MergeComponent scanning misses it without an explicit dep.
                api(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-oauth2-common-impl:$version" else project(":lib-oauth2-common-impl"))
                // SD-JWT format handler needed by OID4VC holder impl
                api(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-sdjwt-impl:$version" else project(":lib-sdjwt-impl"))
                // CBOR / mDoc format handlers needed by OID4VP holder impl
                api(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-cbor-impl:$version" else project(":lib-cbor-impl"))
                api(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-mdoc-core-impl:$version" else project(":lib-mdoc-core-impl"))
                // DID manager + resolver + method impls needed by holder credential proofs
                api(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-did-manager-impl:$version" else project(":lib-did-manager-impl"))
                api(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-did-resolver-impl:$version" else project(":lib-did-resolver-impl"))
                api(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-did-methods-jwk:$version" else project(":lib-did-methods-jwk"))
            }
        }
        val jvmTest by getting {
            dependencies {
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-data-store-blob-impl-fs:$version" else project(":lib-data-store-blob-impl-fs"))
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-core-api-default:$version" else project(":lib-core-api-default"))
                // Software KMS provider needed by WalletBootstrap
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-kms-provider-software:$version" else project(":lib-crypto-kms-provider-software"))
                // In-memory backing stores for BlobService (BlobWalletCredentialStore) and KV metadata index
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-data-store-blob-impl-memory:$version" else project(":lib-data-store-blob-impl-memory"))
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-data-store-kv-impl-memory:$version" else project(":lib-data-store-kv-impl-memory"))
                // Event hub used by DefaultBlobService
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-core-events-impl:$version" else project(":lib-core-events-impl"))
                // DID method impls pulled in by OID4VCI/OID4VP holder graphs
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-did-methods-jwk:$version" else project(":lib-did-methods-jwk"))
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-did-persistence-memory:$version" else project(":lib-did-persistence-memory"))
                // HTTP client impl needed by holder metadata resolution
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-data-link-http-client-impl:$version" else project(":lib-data-link-http-client-impl"))
                // SD-JWT format handler
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-sdjwt-impl:$version" else project(":lib-sdjwt-impl"))
                // CBOR/mDoc format handlers
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-cbor-impl:$version" else project(":lib-cbor-impl"))
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-mdoc-core-impl:$version" else project(":lib-mdoc-core-impl"))
                // DID manager impl
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-did-manager-impl:$version" else project(":lib-did-manager-impl"))
                // DID resolver impl
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-did-resolver-impl:$version" else project(":lib-did-resolver-impl"))
            }
        }
    }
}
