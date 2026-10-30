import com.sphereon.gradle.plugin.configureIosTargetsIfEnabled
import com.sphereon.gradle.plugin.configureLinuxTargetIfEnabled
import com.sphereon.gradle.plugin.configureWasmJsTargetIfEnabled
import org.jetbrains.kotlin.gradle.dsl.JsModuleKind

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
    jvm {
        testRuns.named("test") {
            executionTask.configure {
                useJUnitPlatform()
            }
        }
    }
    run {
        val kmpTargets = (System.getProperty("kmp.targets") ?: "jvm").split(",").map { it.trim().lowercase() }
        if ("all" in kmpTargets || "js" in kmpTargets) {
            js {
                compilerOptions {
                    moduleKind = JsModuleKind.MODULE_ES
                    target = "es2015"
                }
                browser { testTask { enabled = false } }
                nodejs { testTask { useMocha { timeout = "60000" } } }
                binaries.library()
                generateTypeScriptDefinitions()
            }
        }
    }
    configureWasmJsTargetIfEnabled {
        nodejs()
        binaries.library()
        generateTypeScriptDefinitions()
    }
    configureIosTargetsIfEnabled()
    configureLinuxTargetIfEnabled()

    sourceSets {
        findByName("jsTest")?.dependencies {
            implementation(sphereonlib.org.jetbrains.kotlinx.coroutines.core.js)
        }
        val commonMain by getting {
            dependencies {
                implementation(sphereonlib.co.touchlab.skie.configuration.annotations)
                api(if (rootProject.findProperty("idk.consumeCoreAsArtifacts") == "true") "com.sphereon.idk:lib-core-api-public:$version" else project(":lib-core-api-public"))
                api(if (rootProject.findProperty("idk.consumeCoreAsArtifacts") == "true") "com.sphereon.idk:lib-core-events-public:$version" else project(":lib-core-events-public"))
                api(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-core:$version" else project(":lib-crypto-core"))
                api(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-core-public:$version" else project(":lib-crypto-core-public"))

                // VCDM Data Integrity facade and identifier-neutral
                // verification-method resolution used by the common-platform
                // verification adapter. Concrete identifier resolvers are
                // supplied by the deployment graph.
                api(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-data-integrity-proof-public:$version" else project(":lib-crypto-data-integrity-proof-public"))

                // DID manager (for did:jwk kid resolution in JAR signing)
                api(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-did-manager-public:$version" else project(":lib-did-manager-public"))
                api(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-did-core-public:$version" else project(":lib-did-core-public"))
                // Issuer DID documents: an SD-JWT issuer kid must be one of the DID's assertionMethod keys.
                api(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-did-resolver-public:$version" else project(":lib-did-resolver-public"))

                // OAuth2 common and client (for JAR support)
                api(projects.libOauth2CommonPublic)
                api(projects.libOauth2ClientPublic)

                // OID4VP public APIs
                api(projects.libOpenidOid4vpVerifierPublic)
                api(projects.libOpenidOid4vpCommonPublic)
                api(projects.libOpenidOid4vpDcql)
                api(projects.libOpenidOid4vpDcqlStorePublic)

                // KV storage (for KV-backed OID4VP stores)
                api(if (rootProject.findProperty("idk.consumeInfrastructureAsArtifacts") == "true") "com.sphereon.idk:lib-data-store-kv-public:$version" else project(":lib-data-store-kv-public"))
                api(if (rootProject.findProperty("idk.consumeInfrastructureAsArtifacts") == "true") "com.sphereon.idk:lib-data-store-kv-impl:$version" else project(":lib-data-store-kv-impl"))
                api(if (rootProject.findProperty("idk.consumeInfrastructureAsArtifacts") == "true") "com.sphereon.idk:lib-data-store-kv-impl-memory:$version" else project(":lib-data-store-kv-impl-memory"))

                // SD-JWT verification
                api(projects.libSdjwtPublic)

                // Credential status verification SPI + evaluation (impls supplied by the deployment)
                implementation(projects.libStatuslistPublic)

                // JSON-LD context + schema validation for VCDM 2.0
                // (jwt_vc_json-ld) presentations. Mirrors the wiring on the
                // issuer side in lib-openid-oid4vci-issuer-impl.
                api(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-jsonld-public:$version" else project(":lib-jsonld-public"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-jsonld-loader:$version" else project(":lib-jsonld-loader"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-jsonld-processor:$version" else project(":lib-jsonld-processor"))

                // mDoc verification (Fix V-P0-11): MdocValidations + DeviceAuthValidation +
                // SessionTranscriptCborCodec + DeviceResponseCborCodec for OID4VP iso_mdl path.
                api(projects.libMdocCorePublic)

                // mDoc IACA trust anchors flow through the shared X.509 trust loader
                // (`trust.anchors.x509.*` config keys). Same loader X509TrustValidationService uses.
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-trust-x509:$version" else project(":lib-trust-x509"))

                // Serialization
                api(sphereonlib.org.jetbrains.kotlinx.serialization.json)

                // Validation (konform)
                api(sphereonlib.io.konform.konform)

                // HTTP client for metadata resolution
                api(sphereonlib.io.ktor.client.core)
                api(sphereonlib.io.ktor.client.content.negotiation)
                api(sphereonlib.io.ktor.serialization.kotlinx.json)
                // HttpClientFactory abstraction (used for callbacks)
                api(if (rootProject.findProperty("idk.consumeInfrastructureAsArtifacts") == "true") "com.sphereon.idk:lib-data-link-http-client-public:$version" else project(":lib-data-link-http-client-public"))

                api(libs.bundles.app.platform.di)
                api(sphereonlib.software.amazon.app.platform.metro.public)
            }
        }
        val commonTest by getting {
            dependencies {
                implementation(sphereonlib.org.jetbrains.kotlin.test)
                implementation(sphereonlib.org.jetbrains.kotlinx.coroutines.test)
                implementation(if (rootProject.findProperty("idk.consumeCoreAsArtifacts") == "true") "com.sphereon.idk:lib-core-test:$version" else project(":lib-core-test"))
                implementation(if (rootProject.findProperty("idk.consumeCoreAsArtifacts") == "true") "com.sphereon.idk:lib-core-api-default:$version" else project(":lib-core-api-default"))
                implementation(if (rootProject.findProperty("idk.consumeCoreAsArtifacts") == "true") "com.sphereon.idk:lib-core-events-impl:$version" else project(":lib-core-events-impl"))
                // The verifier implementation consumes the VCDM port only. Concrete VCDM and
                // Data Integrity implementations belong to the final test/app graph.
                implementation(project(":lib-openid-oid4vp-verifier-vcdm-impl"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-data-integrity-proof-impl:$version" else project(":lib-crypto-data-integrity-proof-impl"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-data-integrity-proof-eddsa-jcs-2022:$version" else project(":lib-crypto-data-integrity-proof-eddsa-jcs-2022"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-data-integrity-proof-eddsa-rdfc-2022:$version" else project(":lib-crypto-data-integrity-proof-eddsa-rdfc-2022"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-data-integrity-proof-ecdsa-rdfc-2019:$version" else project(":lib-crypto-data-integrity-proof-ecdsa-rdfc-2019"))
                // KvDcqlQueryConfigurationStore binding for the verifier test app graph
                implementation(projects.libOpenidOid4vpDcqlStoreImpl)
                implementation(if (rootProject.findProperty("idk.consumeInfrastructureAsArtifacts") == "true") "com.sphereon.idk:lib-data-link-http-client-impl:$version" else project(":lib-data-link-http-client-impl"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-core-impl:$version" else project(":lib-crypto-core-impl"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-kms-provider-software:$version" else project(":lib-crypto-kms-provider-software"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-did-manager-impl:$version" else project(":lib-did-manager-impl"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-did-resolver-impl:$version" else project(":lib-did-resolver-impl"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-did-methods-key:$version" else project(":lib-did-methods-key"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-did-methods-jwk:$version" else project(":lib-did-methods-jwk"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-did-persistence-memory:$version" else project(":lib-did-persistence-memory"))
                implementation(projects.libOauth2CommonImpl)
                implementation(projects.libOauth2ClientImpl)
                implementation(projects.libOpenidOid4vpHolderImpl)
                implementation(projects.libSdjwtImpl)
                // mdoc impl bindings (MdocValidations, DeviceAuthValidation, *CborCodec impls)
                // are required for the test app graph to satisfy VerifyHolderBindingCommandImpl's
                // mdoc dependencies. Pulls in the CBOR + COSE impls transitively.
                implementation(projects.libMdocCoreImpl)
                implementation(if (rootProject.findProperty("idk.consumeCoreAsArtifacts") == "true") "com.sphereon.idk:lib-cbor-impl:$version" else project(":lib-cbor-impl"))
                // DefaultTrustConfigProvider binding for X509TrustAnchorLoaderImpl.
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-trust-core-impl:$version" else project(":lib-trust-core-impl"))
                implementation(sphereonlib.io.ktor.client.mock)
            }
        }
        val jvmTest by getting {
            // Keep the canonical W3C vectors in oid4vc/common/public; expose that one
            // resource tree to this production-verifier test source set without duplicating
            // fixtures into the verifier module.
            resources.srcDir(rootProject.file("lib/openid/oid4vc/common/public/src/jvmTest/resources"))
            dependencies {
                implementation(if (rootProject.findProperty("idk.consumeCoreAsArtifacts") == "true") "com.sphereon.idk:lib-core-test:$version" else project(":lib-core-test"))
                implementation(if (rootProject.findProperty("idk.consumeCoreAsArtifacts") == "true") "com.sphereon.idk:lib-core-api-default:$version" else project(":lib-core-api-default"))
                implementation(if (rootProject.findProperty("idk.consumeCoreAsArtifacts") == "true") "com.sphereon.idk:lib-core-events-impl:$version" else project(":lib-core-events-impl"))
                implementation(project(":lib-openid-oid4vp-verifier-vcdm-impl"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-data-integrity-proof-impl:$version" else project(":lib-crypto-data-integrity-proof-impl"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-data-integrity-proof-eddsa-jcs-2022:$version" else project(":lib-crypto-data-integrity-proof-eddsa-jcs-2022"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-data-integrity-proof-eddsa-rdfc-2022:$version" else project(":lib-crypto-data-integrity-proof-eddsa-rdfc-2022"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-data-integrity-proof-ecdsa-rdfc-2019:$version" else project(":lib-crypto-data-integrity-proof-ecdsa-rdfc-2019"))
                implementation(projects.libOpenidOid4vpDcqlStoreImpl)
                implementation(if (rootProject.findProperty("idk.consumeInfrastructureAsArtifacts") == "true") "com.sphereon.idk:lib-data-link-http-client-impl:$version" else project(":lib-data-link-http-client-impl"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-core-impl:$version" else project(":lib-crypto-core-impl"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-kms-provider-software:$version" else project(":lib-crypto-kms-provider-software"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-did-manager-impl:$version" else project(":lib-did-manager-impl"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-did-resolver-impl:$version" else project(":lib-did-resolver-impl"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-did-methods-key:$version" else project(":lib-did-methods-key"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-did-methods-jwk:$version" else project(":lib-did-methods-jwk"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-did-persistence-memory:$version" else project(":lib-did-persistence-memory"))
                implementation(projects.libOauth2CommonImpl)
                implementation(projects.libOauth2ClientImpl)
                implementation(projects.libOpenidOid4vpHolderImpl)
                implementation(projects.libSdjwtImpl)
                implementation(projects.libMdocCoreImpl)
                implementation(if (rootProject.findProperty("idk.consumeCoreAsArtifacts") == "true") "com.sphereon.idk:lib-cbor-impl:$version" else project(":lib-cbor-impl"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-trust-core-impl:$version" else project(":lib-trust-core-impl"))
                implementation(sphereonlib.io.ktor.client.mock)
                implementation(sphereonlib.org.jetbrains.kotlin.test)
                implementation(sphereonlib.org.jetbrains.kotlinx.coroutines.test)
            }
        }
    }
}
