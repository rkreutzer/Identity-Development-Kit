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
    jvm()
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
        val commonMain by getting {
            dependencies {
                api(projects.libWalletInteractionPublic)
                api(projects.libWalletPublic)
                api(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-mdoc-core-public:$version" else project(":lib-mdoc-core-public"))
                api(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-mdoc-datatransfer-public:$version" else project(":lib-mdoc-datatransfer-public"))
                api(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-statuslist-public:$version" else project(":lib-statuslist-public"))
                implementation(sphereonlib.org.jetbrains.kotlinx.coroutines.core)
            }
        }
        val commonTest by getting {
            dependencies {
                implementation(kotlin("test"))
                implementation(projects.libWalletInteractionImpl)
                implementation(projects.libWalletInteractionTestFixtures)
                implementation(sphereonlib.org.jetbrains.kotlinx.coroutines.test)
            }
        }
        val jvmTest by getting {
            dependencies {
                implementation(projects.libWalletInteractionHolderWiring)
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-core-impl:$version" else project(":lib-crypto-core-impl"))
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-mdoc-core-impl:$version" else project(":lib-mdoc-core-impl"))
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-mdoc-datatransfer-impl:$version" else project(":lib-mdoc-datatransfer-impl"))
                implementation(projects.libWalletImpl)
                // Product-boundary mso_mdoc issuance/status verification proof: use the actual
                // OID4VCI format handler and status verifier against the wallet store below.
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-openid-oid4vci-issuer-impl:$version" else project(":lib-openid-oid4vci-issuer-impl"))
                // Include the production AS/policy/trust bindings required by the issuer
                // bridge; these are real in-memory/config-backed implementations, not test
                // doubles.
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-oauth2-server-authorization-impl:$version" else project(":lib-oauth2-server-authorization-impl"))
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-oauth2-server-resource-impl:$version" else project(":lib-oauth2-server-resource-impl"))
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-openid-oid4vci-rest-impl:$version" else project(":lib-openid-oid4vci-rest-impl"))
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-openid-oid4vc-common-impl:$version" else project(":lib-openid-oid4vc-common-impl"))
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-openid-oid4vp-verifier-impl:$version" else project(":lib-openid-oid4vp-verifier-impl"))
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-openid-oid4vp-dcql-store-impl:$version" else project(":lib-openid-oid4vp-dcql-store-impl"))
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-openid-oid4vp-holder-impl:$version" else project(":lib-openid-oid4vp-holder-impl"))
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:services-oid4vci-issuer-rest:$version" else project(":services-oid4vci-issuer-rest"))
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-trust-core-impl:$version" else project(":lib-trust-core-impl"))
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-statuslist-impl:$version" else project(":lib-statuslist-impl"))
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:services-statuslist-rest:$version" else project(":services-statuslist-rest"))
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-trust-x509:$version" else project(":lib-trust-x509"))
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-data-store-blob-impl-memory:$version" else project(":lib-data-store-blob-impl-memory"))
                // The integration graph composes the issuer's public asset-content descriptors.
                // Include their actual owner and blob service, rather than a fixture-only binding.
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-data-store-asset-impl:$version" else project(":lib-data-store-asset-impl"))
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-data-store-blob-impl:$version" else project(":lib-data-store-blob-impl"))
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-data-store-kv-impl-memory:$version" else project(":lib-data-store-kv-impl-memory"))
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-core-events-impl:$version" else project(":lib-core-events-impl"))
                implementation(sphereonlib.io.ktor.client.mock)
                implementation(projects.libWalletWscdTestFixtures)
                // This source set hosts Iso18013MdocIntegrationTestAppGraph. The wallet
                // graph includes OID4VP holder bindings, whose W3C presentation path
                // requires the Data Integrity command and cryptosuite contributions.
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-data-integrity-proof-impl:$version" else project(":lib-crypto-data-integrity-proof-impl"))
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-data-integrity-proof-eddsa-jcs-2022:$version" else project(":lib-crypto-data-integrity-proof-eddsa-jcs-2022"))
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-data-integrity-proof-eddsa-rdfc-2022:$version" else project(":lib-crypto-data-integrity-proof-eddsa-rdfc-2022"))
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-data-integrity-proof-ecdsa-rdfc-2019:$version" else project(":lib-crypto-data-integrity-proof-ecdsa-rdfc-2019"))
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-openid-oid4vp-verifier-vcdm-impl:$version" else project(":lib-openid-oid4vp-verifier-vcdm-impl"))
                implementation(libs.bundles.app.platform.di)
                implementation(sphereonlib.software.amazon.app.platform.metro.public)
                implementation(sphereonlib.software.amazon.app.platform.metro.impl)
                implementation(sphereonlib.io.mockk.mockk)
            }
        }
    }
}
