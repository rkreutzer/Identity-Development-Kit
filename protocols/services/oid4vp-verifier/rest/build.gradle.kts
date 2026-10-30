plugins {
    alias(sphereonplug.plugins.org.jetbrains.kotlin.multiplatform)
    alias(sphereonplug.plugins.org.jetbrains.kotlin.plugin.serialization)
    alias(sphereonplug.plugins.com.google.devtools.ksp.com.google.devtools.ksp.gradle.plugin)
    alias(sphereonplug.plugins.dev.zacsweers.metro)
    // Maven publications (service-deployable alone does not register publish tasks).
    alias(sphereonplug.plugins.com.sphereon.gradle.plugin.project.publication)
    id("com.sphereon.gradle.plugin.service-deployable")
}
metro {
}
serviceDeployable {
    mainClass.set("com.sphereon.openid.oid4vp.verifier.ktor.Oid4vpVerifierKtorServerKt")
}

kotlin {
    jvm {
        testRuns.named("test") {
            executionTask.configure {
                useJUnitPlatform()
                // The named-verifier proof needs a separately running local stack, so ordinary runs leave it out
                // and `-Poid4vp.localStackTest=true` selects it alone.
                val localStackTest = "com.sphereon.openid.oid4vp.universal.impl.NamedVerifierLocalStackTest"
                if (project.findProperty("oid4vp.localStackTest") == "true") {
                    filter.includeTestsMatching(localStackTest)
                } else {
                    filter.excludeTestsMatching(localStackTest)
                }
            }
        }
    }

    sourceSets {
        val commonMain by getting {
            dependencies {
                // Reusable OID4VP REST adapters (verifier + universal) — the adapter classes
                // and endpoint commands this standalone server mounts. `api` so the server's
                // jvmMain and the test source sets see them.
                api(if (rootProject.findProperty("idk.consumeProtocolsAsArtifacts") == "true") "com.sphereon.idk:lib-openid-oid4vp-verifier-rest:$version" else project(":lib-openid-oid4vp-verifier-rest"))

                // OID4VP Verifier + Universal service logic
                implementation(if (rootProject.findProperty("idk.consumeProtocolsAsArtifacts") == "true") "com.sphereon.idk:lib-openid-oid4vp-verifier-public:$version" else project(":lib-openid-oid4vp-verifier-public"))
                implementation(if (rootProject.findProperty("idk.consumeProtocolsAsArtifacts") == "true") "com.sphereon.idk:lib-openid-oid4vp-verifier-impl:$version" else project(":lib-openid-oid4vp-verifier-impl"))
                // This standalone service owns the Metro composition root. VCDM verification and
                // each supported Data Integrity cryptosuite are implementation details of library
                // modules, so their contributions are not visible through verifier-impl's
                // transitive `implementation` edges. Keep the complete verifier graph explicit.
                implementation(project(":lib-openid-oid4vp-verifier-vcdm-impl"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-data-integrity-proof-impl:$version" else project(":lib-crypto-data-integrity-proof-impl"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-data-integrity-proof-eddsa-jcs-2022:$version" else project(":lib-crypto-data-integrity-proof-eddsa-jcs-2022"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-data-integrity-proof-eddsa-rdfc-2022:$version" else project(":lib-crypto-data-integrity-proof-eddsa-rdfc-2022"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-data-integrity-proof-ecdsa-rdfc-2019:$version" else project(":lib-crypto-data-integrity-proof-ecdsa-rdfc-2019"))

                // Credential status verification: brings the StatusListResolver binding + the two
                // CredentialStatusVerifier set members so the verifier actually checks status lists.
                implementation(if (rootProject.findProperty("idk.consumeProtocolsAsArtifacts") == "true") "com.sphereon.idk:lib-statuslist-public:$version" else project(":lib-statuslist-public"))
                implementation(if (rootProject.findProperty("idk.consumeProtocolsAsArtifacts") == "true") "com.sphereon.idk:lib-statuslist-impl:$version" else project(":lib-statuslist-impl"))
                implementation(if (rootProject.findProperty("idk.consumeProtocolsAsArtifacts") == "true") "com.sphereon.idk:lib-openid-oid4vp-universal-public:$version" else project(":lib-openid-oid4vp-universal-public"))
                implementation(if (rootProject.findProperty("idk.consumeProtocolsAsArtifacts") == "true") "com.sphereon.idk:lib-openid-oid4vp-universal-impl:$version" else project(":lib-openid-oid4vp-universal-impl"))
                implementation(if (rootProject.findProperty("idk.consumeProtocolsAsArtifacts") == "true") "com.sphereon.idk:lib-openid-oid4vp-common-public:$version" else project(":lib-openid-oid4vp-common-public"))
                implementation(if (rootProject.findProperty("idk.consumeProtocolsAsArtifacts") == "true") "com.sphereon.idk:lib-openid-oid4vp-dcql:$version" else project(":lib-openid-oid4vp-dcql"))
                // DCQL store: KvDcqlQueryConfigurationStore binding (required by THIS
                // standalone server's own graph) + admin ServiceCommands + REST surface. A
                // consuming assembly that brings its own DCQL store depends on
                // lib-openid-oid4vp-verifier-rest directly instead of this module.
                implementation(if (rootProject.findProperty("idk.consumeProtocolsAsArtifacts") == "true") "com.sphereon.idk:lib-openid-oid4vp-dcql-store-impl:$version" else project(":lib-openid-oid4vp-dcql-store-impl"))
                implementation(if (rootProject.findProperty("idk.consumeProtocolsAsArtifacts") == "true") "com.sphereon.idk:lib-openid-oid4vp-dcql-store-rest:$version" else project(":lib-openid-oid4vp-dcql-store-rest"))
                // JsonLd validators are reached transitively through verifier-impl
                // with implementation scope; the Ktor server graph needs them on
                // the compile classpath so Metro can discover their @Inject ctors.
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-jsonld-loader:$version" else project(":lib-jsonld-loader"))

                // Core
                implementation(if (rootProject.findProperty("idk.consumeCoreAsArtifacts") == "true") "com.sphereon.idk:lib-core-api-public:$version" else project(":lib-core-api-public"))
                implementation(if (rootProject.findProperty("idk.consumeCoreAsArtifacts") == "true") "com.sphereon.idk:lib-core-api-default:$version" else project(":lib-core-api-default"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-core:$version" else project(":lib-crypto-core"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-core-public:$version" else project(":lib-crypto-core-public"))

                // KV storage (for session stores)
                implementation(if (rootProject.findProperty("idk.consumeInfrastructureAsArtifacts") == "true") "com.sphereon.idk:lib-data-store-kv-public:$version" else project(":lib-data-store-kv-public"))
                implementation(if (rootProject.findProperty("idk.consumeInfrastructureAsArtifacts") == "true") "com.sphereon.idk:lib-data-store-kv-impl:$version" else project(":lib-data-store-kv-impl"))
                implementation(if (rootProject.findProperty("idk.consumeInfrastructureAsArtifacts") == "true") "com.sphereon.idk:lib-data-store-kv-impl-memory:$version" else project(":lib-data-store-kv-impl-memory"))

                // SD-JWT
                implementation(if (rootProject.findProperty("idk.consumeProtocolsAsArtifacts") == "true") "com.sphereon.idk:lib-sdjwt-public:$version" else project(":lib-sdjwt-public"))

                // HTTP client (for callbacks)
                implementation(if (rootProject.findProperty("idk.consumeInfrastructureAsArtifacts") == "true") "com.sphereon.idk:lib-data-link-http-client-public:$version" else project(":lib-data-link-http-client-public"))

                // DI (Metro)
                implementation(libs.bundles.app.platform.di)
                implementation(sphereonlib.software.amazon.app.platform.metro.public)
                implementation(sphereonlib.software.amazon.app.platform.metro.impl)

                // Serialization
                implementation(sphereonlib.org.jetbrains.kotlinx.serialization.json)
                implementation(sphereonlib.org.jetbrains.kotlinx.coroutines.core)

                // Ktor client (for HTTP operations in commands)
                implementation(sphereonlib.io.ktor.client.core)
                implementation(sphereonlib.io.ktor.client.content.negotiation)
                implementation(sphereonlib.io.ktor.serialization.kotlinx.json)
            }
        }

        val commonTest by getting {
            dependencies {
                implementation(kotlin("test"))
                implementation(sphereonlib.org.jetbrains.kotlinx.coroutines.test)
                implementation(if (rootProject.findProperty("idk.consumeCoreAsArtifacts") == "true") "com.sphereon.idk:lib-core-test:$version" else project(":lib-core-test"))
                implementation(if (rootProject.findProperty("idk.consumeCoreAsArtifacts") == "true") "com.sphereon.idk:lib-core-api-default:$version" else project(":lib-core-api-default"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-core-impl:$version" else project(":lib-crypto-core-impl"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-kms-provider-software:$version" else project(":lib-crypto-kms-provider-software"))
                implementation(if (rootProject.findProperty("idk.consumeInfrastructureAsArtifacts") == "true") "com.sphereon.idk:lib-data-link-http-client-impl:$version" else project(":lib-data-link-http-client-impl"))
                implementation(if (rootProject.findProperty("idk.consumeProtocolsAsArtifacts") == "true") "com.sphereon.idk:lib-oauth2-common-impl:$version" else project(":lib-oauth2-common-impl"))
                implementation(if (rootProject.findProperty("idk.consumeProtocolsAsArtifacts") == "true") "com.sphereon.idk:lib-oauth2-client-impl:$version" else project(":lib-oauth2-client-impl"))
                implementation(if (rootProject.findProperty("idk.consumeProtocolsAsArtifacts") == "true") "com.sphereon.idk:lib-openid-oid4vp-holder-impl:$version" else project(":lib-openid-oid4vp-holder-impl"))
                implementation(if (rootProject.findProperty("idk.consumeProtocolsAsArtifacts") == "true") "com.sphereon.idk:lib-sdjwt-impl:$version" else project(":lib-sdjwt-impl"))
                implementation(sphereonlib.io.ktor.client.mock)
            }
        }

        val jvmMain by getting {
            dependencies {
                // Ktor server
                implementation(if (rootProject.findProperty("idk.consumeInfrastructureAsArtifacts") == "true") "com.sphereon.idk:ktor-server-kotlin-inject:$version" else project(":ktor-server-kotlin-inject"))
                // YAML config (must be direct dep for Metro to discover YamlFileAppPropertySourceImpl)
                implementation(if (rootProject.findProperty("idk.consumeCoreAsArtifacts") == "true") "com.sphereon.idk:lib-conf-yaml:$version" else project(":lib-conf-yaml"))
                implementation(sphereonlib.io.ktor.server.core)
                implementation(sphereonlib.io.ktor.server.cio)
                implementation(sphereonlib.io.ktor.server.content.negotiation)
                implementation(sphereonlib.io.ktor.server.status.pages)
                implementation(sphereonlib.io.ktor.serialization.kotlinx.json)

                // Crypto providers for runtime
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-core-impl:$version" else project(":lib-crypto-core-impl"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-kms-provider-software:$version" else project(":lib-crypto-kms-provider-software"))
                implementation(if (rootProject.findProperty("idk.consumeInfrastructureAsArtifacts") == "true") "com.sphereon.idk:lib-data-link-http-client-impl:$version" else project(":lib-data-link-http-client-impl"))

                // DID manager (for did:jwk kid resolution in JAR signing)
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-did-manager-public:$version" else project(":lib-did-manager-public"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-did-manager-impl:$version" else project(":lib-did-manager-impl"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-did-persistence-api:$version" else project(":lib-did-persistence-api"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-did-persistence-memory:$version" else project(":lib-did-persistence-memory"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-did-resolver-impl:$version" else project(":lib-did-resolver-impl"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-did-methods-jwk:$version" else project(":lib-did-methods-jwk"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-did-methods-key:$version" else project(":lib-did-methods-key"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-did-methods-web:$version" else project(":lib-did-methods-web"))

                // OAuth2 (needed for JAR support in verifier)
                implementation(if (rootProject.findProperty("idk.consumeProtocolsAsArtifacts") == "true") "com.sphereon.idk:lib-oauth2-common-impl:$version" else project(":lib-oauth2-common-impl"))
                implementation(if (rootProject.findProperty("idk.consumeProtocolsAsArtifacts") == "true") "com.sphereon.idk:lib-oauth2-client-impl:$version" else project(":lib-oauth2-client-impl"))

                // SD-JWT (runtime impl for verification bindings)
                implementation(if (rootProject.findProperty("idk.consumeProtocolsAsArtifacts") == "true") "com.sphereon.idk:lib-sdjwt-impl:$version" else project(":lib-sdjwt-impl"))

                // mDoc verification bindings used by VerifyHolderBindingCommandImpl
                // (MdocValidations, DeviceAuthValidation, DeviceResponseCborCodec).
                // libMdocCoreImpl pulls libCborImpl + COSE bindings transitively.
                implementation(if (rootProject.findProperty("idk.consumeProtocolsAsArtifacts") == "true") "com.sphereon.idk:lib-mdoc-core-impl:$version" else project(":lib-mdoc-core-impl"))
                implementation(if (rootProject.findProperty("idk.consumeCoreAsArtifacts") == "true") "com.sphereon.idk:lib-cbor-impl:$version" else project(":lib-cbor-impl"))

                // Trust framework: X509TrustAnchorLoaderImpl feeds the mdoc IACA path
                // (and X509TrustValidationService); DefaultTrustConfigProvider binds
                // `trust.*` config keys.
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-trust-x509:$version" else project(":lib-trust-x509"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-trust-core-impl:$version" else project(":lib-trust-core-impl"))

                // Events
                implementation(if (rootProject.findProperty("idk.consumeCoreAsArtifacts") == "true") "com.sphereon.idk:lib-core-events-impl:$version" else project(":lib-core-events-impl"))
            }
        }
    }
}
