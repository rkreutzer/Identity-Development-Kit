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
                api(projects.libWalletWscaPublic)
                // IssuerSigned/MSO codecs derive per-instance mdoc validity for presentation selection.
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-mdoc-core-impl:$version" else project(":lib-mdoc-core-impl"))
                api(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-credential-claims-mapper-public:$version" else project(":lib-credential-claims-mapper-public"))
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-credential-claims-mapper-impl:$version" else project(":lib-credential-claims-mapper-impl"))
                api(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-data-integrity-proof-public:$version" else project(":lib-crypto-data-integrity-proof-public"))
                // Production Data Integrity holder signing uses the concrete cryptosuites and
                // JsonLdProcessor (see Oid4vpDataIntegrityCryptosuiteSigner).
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-data-integrity-proof-eddsa-jcs-2022:$version" else project(":lib-crypto-data-integrity-proof-eddsa-jcs-2022"))
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-data-integrity-proof-eddsa-rdfc-2022:$version" else project(":lib-crypto-data-integrity-proof-eddsa-rdfc-2022"))
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-data-integrity-proof-ecdsa-rdfc-2019:$version" else project(":lib-crypto-data-integrity-proof-ecdsa-rdfc-2019"))
                api(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-jsonld-public:$version" else project(":lib-jsonld-public"))
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-jsonld-processor:$version" else project(":lib-jsonld-processor"))
                api(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-openid-oid4vp-holder-public:$version" else project(":lib-openid-oid4vp-holder-public"))
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-openid-oid4vp-holder-impl:$version" else project(":lib-openid-oid4vp-holder-impl"))
                api(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-openid-oid4vp-common-public:$version" else project(":lib-openid-oid4vp-common-public"))
                api(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-openid-oid4vp-dcql:$version" else project(":lib-openid-oid4vp-dcql"))
                // SD-JWT codec (parse/serialize) reused by SecureComponentOid4vpSdJwtHolderBindingProvider
                // to pre-sign the RFC 9901 Key Binding JWT through Wsca instead of the generic
                // holder's KMS-managed-identifier path.
                api(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-sdjwt-public:$version" else project(":lib-sdjwt-public"))
                api(sphereonlib.org.jetbrains.kotlinx.serialization.json)
            }
        }
        val commonTest by getting {
            dependencies {
                implementation(kotlin("test"))
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-data-integrity-proof-impl:$version" else project(":lib-crypto-data-integrity-proof-impl"))
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-data-integrity-proof-eddsa-jcs-2022:$version" else project(":lib-crypto-data-integrity-proof-eddsa-jcs-2022"))
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-data-integrity-proof-eddsa-rdfc-2022:$version" else project(":lib-crypto-data-integrity-proof-eddsa-rdfc-2022"))
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-data-integrity-proof-ecdsa-rdfc-2019:$version" else project(":lib-crypto-data-integrity-proof-ecdsa-rdfc-2019"))
                implementation(if (rootProject.findProperty("idk.consumeLowerAsArtifacts") == "true") "com.sphereon.idk:lib-jsonld-loader:$version" else project(":lib-jsonld-loader"))
                implementation(sphereonlib.org.jetbrains.kotlinx.coroutines.test)
            }
        }
    }
}
