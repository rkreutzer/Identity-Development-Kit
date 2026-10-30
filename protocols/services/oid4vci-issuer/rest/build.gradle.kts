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
    mainClass.set("com.sphereon.openid.oid4vci.issuer.ktor.Oid4vciIssuerKtorServerKt")
}

kotlin {
    jvm {
        testRuns.named("test") {
            executionTask.configure {
                useJUnitPlatform()
            }
        }
    }

    sourceSets {
        val commonMain by getting {
            dependencies {
                api(if (rootProject.findProperty("idk.consumeProtocolsAsArtifacts") == "true") "com.sphereon.idk:lib-openid-oid4vci-issuer-rest:$version" else project(":lib-openid-oid4vci-issuer-rest"))
                // OID4VCI REST API (backend credential offer management)
                implementation(if (rootProject.findProperty("idk.consumeProtocolsAsArtifacts") == "true") "com.sphereon.idk:lib-openid-oid4vci-rest-public:$version" else project(":lib-openid-oid4vci-rest-public"))
                implementation(if (rootProject.findProperty("idk.consumeProtocolsAsArtifacts") == "true") "com.sphereon.idk:lib-openid-oid4vci-rest-impl:$version" else project(":lib-openid-oid4vci-rest-impl"))

                // OID4VCI Issuer service logic
                implementation(if (rootProject.findProperty("idk.consumeProtocolsAsArtifacts") == "true") "com.sphereon.idk:lib-openid-oid4vci-issuer-public:$version" else project(":lib-openid-oid4vci-issuer-public"))
                implementation(if (rootProject.findProperty("idk.consumeProtocolsAsArtifacts") == "true") "com.sphereon.idk:lib-openid-oid4vci-issuer-impl:$version" else project(":lib-openid-oid4vci-issuer-impl"))

                // The service is the Metro composition root. Contributions hidden behind an
                // `implementation` dependency of issuer-impl are intentionally not re-exported,
                // so include the Data Integrity command and cryptosuite implementations here.
                // This makes `ldp_vc` issuance use the same real Add Proof pipeline as the
                // library API instead of leaving AddProofServiceCommand unbound at runtime.
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-data-integrity-proof-impl:$version" else project(":lib-crypto-data-integrity-proof-impl"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-data-integrity-proof-eddsa-jcs-2022:$version" else project(":lib-crypto-data-integrity-proof-eddsa-jcs-2022"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-data-integrity-proof-eddsa-rdfc-2022:$version" else project(":lib-crypto-data-integrity-proof-eddsa-rdfc-2022"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-data-integrity-proof-ecdsa-rdfc-2019:$version" else project(":lib-crypto-data-integrity-proof-ecdsa-rdfc-2019"))

                // HttpAsBridge verifies JWT access tokens through the OAuth2 resource-server
                // command registry. Include the implementation so Metro can contribute the
                // VerifyJwtCommand descriptor to the standalone issuer service graph.
                implementation(if (rootProject.findProperty("idk.consumeProtocolsAsArtifacts") == "true") "com.sphereon.idk:lib-oauth2-server-resource-impl:$version" else project(":lib-oauth2-server-resource-impl"))

                // Credential status list: the driver/signer/resolver/enricher bindings (the enricher
                // embeds status into issued credentials; the driver hosts the signed token).
                // statuslist-impl brings the in-memory reference driver by default. The public token
                // hosting + simple by-index admin REST come from the standalone services-statuslist-rest
                // module (co-hosted here; not coupled to OID4VCI).
                implementation(if (rootProject.findProperty("idk.consumeProtocolsAsArtifacts") == "true") "com.sphereon.idk:lib-statuslist-public:$version" else project(":lib-statuslist-public"))
                implementation(if (rootProject.findProperty("idk.consumeProtocolsAsArtifacts") == "true") "com.sphereon.idk:lib-statuslist-impl:$version" else project(":lib-statuslist-impl"))
                implementation(projects.servicesStatuslistRest)

                implementation(if (rootProject.findProperty("idk.consumeProtocolsAsArtifacts") == "true") "com.sphereon.idk:lib-openid-oid4vci-common-public:$version" else project(":lib-openid-oid4vci-common-public"))

                // Public design-asset path constants + per-tenant URI resolver (PublicDesignAssetPaths):
                // the metadata + VCT endpoints rewrite stored RELATIVE design-asset URIs to absolute
                // per-tenant URLs at serve time. Pure model module, no heavy transitive deps.
                implementation(if (rootProject.findProperty("idk.consumeInfrastructureAsArtifacts") == "true") "com.sphereon.idk:lib-data-store-credential-design-public:$version" else project(":lib-data-store-credential-design-public"))

                // Public design-asset descriptors require the real tenant asset content command.
                // Keep its storage implementations visible to this standalone Metro composition
                // root, including when infrastructure libraries are consumed as Maven artifacts.
                implementation(if (rootProject.findProperty("idk.consumeInfrastructureAsArtifacts") == "true") "com.sphereon.idk:lib-data-store-asset-impl:$version" else project(":lib-data-store-asset-impl"))
                implementation(if (rootProject.findProperty("idk.consumeInfrastructureAsArtifacts") == "true") "com.sphereon.idk:lib-data-store-blob-impl:$version" else project(":lib-data-store-blob-impl"))
                implementation(if (rootProject.findProperty("idk.consumeInfrastructureAsArtifacts") == "true") "com.sphereon.idk:lib-data-store-blob-impl-memory:$version" else project(":lib-data-store-blob-impl-memory"))

                // JSON-LD validation bindings — `VcLdJsonJwtFormatHandler` (in
                // libOpenidOid4vciIssuerImpl) injects ValidateJsonLdContextServiceCommand
                // and ValidateJsonLdSchemaServiceCommand. The standalone Ktor server's
                // AppGraph in this module composes the full DI graph, so the binding
                // impls from lib-jsonld-loader must be on the runtime classpath.
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-jsonld-public:$version" else project(":lib-jsonld-public"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-jsonld-loader:$version" else project(":lib-jsonld-loader"))

                // Shared OID4VC types + QR code service
                implementation(if (rootProject.findProperty("idk.consumeProtocolsAsArtifacts") == "true") "com.sphereon.idk:lib-openid-oid4vc-common-public:$version" else project(":lib-openid-oid4vc-common-public"))
                implementation(if (rootProject.findProperty("idk.consumeProtocolsAsArtifacts") == "true") "com.sphereon.idk:lib-openid-oid4vc-common-impl:$version" else project(":lib-openid-oid4vc-common-impl"))

                // Core
                implementation(if (rootProject.findProperty("idk.consumeCoreAsArtifacts") == "true") "com.sphereon.idk:lib-core-api-public:$version" else project(":lib-core-api-public"))
                implementation(if (rootProject.findProperty("idk.consumeCoreAsArtifacts") == "true") "com.sphereon.idk:lib-core-api-default:$version" else project(":lib-core-api-default"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-core-public:$version" else project(":lib-crypto-core-public"))

                // KV storage (for session stores)
                implementation(if (rootProject.findProperty("idk.consumeInfrastructureAsArtifacts") == "true") "com.sphereon.idk:lib-data-store-kv-public:$version" else project(":lib-data-store-kv-public"))
                implementation(if (rootProject.findProperty("idk.consumeInfrastructureAsArtifacts") == "true") "com.sphereon.idk:lib-data-store-kv-impl:$version" else project(":lib-data-store-kv-impl"))
                implementation(if (rootProject.findProperty("idk.consumeInfrastructureAsArtifacts") == "true") "com.sphereon.idk:lib-data-store-kv-impl-memory:$version" else project(":lib-data-store-kv-impl-memory"))

                // HTTP client
                implementation(if (rootProject.findProperty("idk.consumeInfrastructureAsArtifacts") == "true") "com.sphereon.idk:lib-data-link-http-client-public:$version" else project(":lib-data-link-http-client-public"))

                // DI
                implementation(libs.bundles.app.platform.di)
                implementation(sphereonlib.software.amazon.app.platform.metro.public)
                implementation(sphereonlib.software.amazon.app.platform.metro.impl)

                // Serialization & concurrency
                implementation(sphereonlib.org.jetbrains.kotlinx.serialization.json)
                implementation(sphereonlib.org.jetbrains.kotlinx.coroutines.core)

                // Ktor client
                implementation(sphereonlib.io.ktor.client.core)
                implementation(sphereonlib.io.ktor.client.content.negotiation)
                implementation(sphereonlib.io.ktor.serialization.kotlinx.json)
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

                // Crypto & storage implementations
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-core-impl:$version" else project(":lib-crypto-core-impl"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-kms-provider-software:$version" else project(":lib-crypto-kms-provider-software"))
                implementation(if (rootProject.findProperty("idk.consumeInfrastructureAsArtifacts") == "true") "com.sphereon.idk:lib-data-link-http-client-impl:$version" else project(":lib-data-link-http-client-impl"))

                // CBOR (needed by mdoc format handler DI)
                implementation(if (rootProject.findProperty("idk.consumeCoreAsArtifacts") == "true") "com.sphereon.idk:lib-cbor-impl:$version" else project(":lib-cbor-impl"))

                // DID manager (for signing key kid resolution via DID providers)
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-did-manager-public:$version" else project(":lib-did-manager-public"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-did-manager-impl:$version" else project(":lib-did-manager-impl"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-did-persistence-api:$version" else project(":lib-did-persistence-api"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-did-persistence-memory:$version" else project(":lib-did-persistence-memory"))

                // DID resolvers (for proof verification with did:jwk / did:key) + did:web signing/resolution.
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-did-resolver-impl:$version" else project(":lib-did-resolver-impl"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-did-methods-jwk:$version" else project(":lib-did-methods-jwk"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-did-methods-key:$version" else project(":lib-did-methods-key"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-did-methods-web:$version" else project(":lib-did-methods-web"))
                // Public DID-document hosting endpoint (/.well-known/did.json). The issuer contributes
                // its own DidHostingProvider (IssuerDidWebHostingProvider) that this endpoint serves.
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:services-did-hosting-rest:$version" else project(":services-did-hosting-rest"))

                // SD-JWT (for JWS verification of proofs)
                implementation(if (rootProject.findProperty("idk.consumeProtocolsAsArtifacts") == "true") "com.sphereon.idk:lib-sdjwt-impl:$version" else project(":lib-sdjwt-impl"))

                // OAuth2 (for AS bridge)
                implementation(if (rootProject.findProperty("idk.consumeProtocolsAsArtifacts") == "true") "com.sphereon.idk:lib-oauth2-common-public:$version" else project(":lib-oauth2-common-public"))
                implementation(if (rootProject.findProperty("idk.consumeProtocolsAsArtifacts") == "true") "com.sphereon.idk:lib-oauth2-common-impl:$version" else project(":lib-oauth2-common-impl"))
                implementation(if (rootProject.findProperty("idk.consumeProtocolsAsArtifacts") == "true") "com.sphereon.idk:lib-oauth2-server-authorization-public:$version" else project(":lib-oauth2-server-authorization-public"))
                implementation(if (rootProject.findProperty("idk.consumeProtocolsAsArtifacts") == "true") "com.sphereon.idk:lib-oauth2-server-authorization-impl:$version" else project(":lib-oauth2-server-authorization-impl"))
            }
        }
        val commonTest by getting {
            dependencies {
                implementation(kotlin("test"))
                implementation(sphereonlib.org.jetbrains.kotlinx.coroutines.test)
            }
        }
    }
}
