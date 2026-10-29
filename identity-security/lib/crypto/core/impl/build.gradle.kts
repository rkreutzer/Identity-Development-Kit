import com.sphereon.gradle.plugin.configureIosTargetsIfEnabled
import com.sphereon.gradle.plugin.configureLinuxTargetIfEnabled
import com.sphereon.gradle.plugin.configureWasmJsTargetIfEnabled

plugins {
    alias(sphereonplug.plugins.org.jetbrains.kotlin.multiplatform)
    alias(sphereonplug.plugins.com.sphereon.gradle.plugin.npm.publication)
    alias(sphereonplug.plugins.org.jetbrains.kotlin.plugin.serialization)
    alias(sphereonplug.plugins.com.sphereon.gradle.plugin.project.publication)
    alias(sphereonplug.plugins.dev.zacsweers.metro)
    id("maven-publish")
    alias(sphereonplug.plugins.org.jetbrains.kotlinx.kover)
}
metro {
}

kotlin {
    kotlin.applyDefaultHierarchyTemplate()
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
                nodejs {
                    testTask {
                        useMocha {
                            timeout = "40000"
                        }
                    }
                    binaries.library()
                    generateTypeScriptDefinitions()
                }
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
                api(if (rootProject.findProperty("idk.consumeCoreAsArtifacts") == "true") "com.sphereon.idk:lib-core-compat-annotations:$version" else project(":lib-core-compat-annotations"))
                implementation(if (rootProject.findProperty("idk.consumeCoreAsArtifacts") == "true") "com.sphereon.idk:lib-compression:$version" else project(":lib-compression"))
                // Public API
                api(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-core-public:$version" else project(":lib-crypto-core-public"))
                api(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-key-persistence-api:$version" else project(":lib-crypto-key-persistence-api"))

                implementation(sphereonlib.org.jetbrains.kotlinx.atomicfu)

                // DI dependencies
                implementation(libs.bundles.app.platform.di)
                api(if (rootProject.findProperty("idk.consumeCoreAsArtifacts") == "true") "com.sphereon.idk:lib-core-api-default:$version" else project(":lib-core-api-default"))
                implementation(if (rootProject.findProperty("idk.consumeCoreAsArtifacts") == "true") "com.sphereon.idk:lib-cbor-impl:$version" else project(":lib-cbor-impl"))

                // Dependencies from kms-common-impl
                implementation(sphereonlib.io.ktor.client.core)
                implementation(sphereonlib.org.jetbrains.kotlinx.serialization.cbor)
                implementation(sphereonlib.dev.whyoleg.cryptography.core)
                implementation(sphereonlib.dev.whyoleg.cryptography.provider.optimal)
                implementation(sphereonlib.org.jetbrains.kotlinx.io.core)
            }
        }
        val commonTest by getting {
            dependencies {
                implementation(kotlin("test"))
                implementation(if (rootProject.findProperty("idk.consumeInfrastructureAsArtifacts") == "true") "com.sphereon.idk:lib-data-link-http-client-impl:$version" else project(":lib-data-link-http-client-impl"))
                implementation(sphereonlib.org.jetbrains.kotlinx.coroutines.test)
                implementation(sphereonlib.org.kotlincrypto.core.digest)
                implementation(sphereonlib.org.kotlincrypto.hash.sha1)
                implementation(sphereonlib.org.kotlincrypto.hash.sha2)
                implementation(sphereonlib.software.amazon.app.platform.metro.impl)
                // Dependencies from kms-common-impl tests
                implementation(if (rootProject.findProperty("idk.consumeCoreAsArtifacts") == "true") "com.sphereon.idk:lib-core-api-default:$version" else project(":lib-core-api-default"))
                implementation(if (rootProject.findProperty("idk.consumeCoreAsArtifacts") == "true") "com.sphereon.idk:lib-core-test:$version" else project(":lib-core-test"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-kms-provider-software:$version" else project(":lib-crypto-kms-provider-software"))
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-key-persistence-impl:$version" else project(":lib-crypto-key-persistence-impl"))
            }
        }
        // libsodium-bindings backs ChaCha20Poly1305Aead (ChaCha20Poly1305EncryptionService) on
        // JVM and native. It publishes no wasmJs artifact (the wasmJsMain actual throws), and its
        // JS externals cannot load as ES modules, so jsMain has its own @noble/ciphers actual.
        val nonWasmMain by creating {
            dependsOn(commonMain)
            dependencies {
                implementation(sphereonlib.com.ionspin.kotlin.multiplatform.crypto.libsodium.bindings)
            }
        }
        // ChaCha20Poly1305EncryptionServiceTest exercises libsodium, so it cannot run on wasmJs.
        val nonWasmTest by creating {
            dependsOn(commonTest)
        }
        val jvmMain by getting {
            dependsOn(nonWasmMain)
            dependencies {
                implementation(sphereonlib.dev.whyoleg.cryptography.provider.jdk)
            }
        }
        val jvmTest by getting {
            dependsOn(nonWasmTest)
            dependencies {
                implementation(sphereonlib.io.ktor.client.cio.jvm)
                implementation(if (rootProject.findProperty("idk.consumeIdentitySecurityAsArtifacts") == "true") "com.sphereon.idk:lib-crypto-kms-provider-software:$version" else project(":lib-crypto-kms-provider-software"))
                implementation(sphereonlib.io.mockk.mockk)
                implementation(sphereonlib.io.ktor.client.mock)
                // nimbus-jose-jwt: independent JOSE library used by JweCrossStackInteropTest to
                // prove IDK-emitted JWEs decrypt under a third-party stack and vice versa.
                // RFC 7516 wire-format compatibility is the contract every JOSE library must
                // honour; the test guards against IDK drifting into a non-interop emission path.
                implementation("com.nimbusds:nimbus-jose-jwt:9.40")
            }
        }
        // Route native main through nonWasmMain for the libsodium AEAD actual. js and native tests
        // both run the AEAD tests through nonWasmTest (wasmJs uses the throwing actual).
        findByName("nativeMain")?.dependsOn(nonWasmMain)
        findByName("jsTest")?.dependsOn(nonWasmTest)
        findByName("nativeTest")?.dependsOn(nonWasmTest)
        findByName("jsMain")?.dependencies {
            implementation(npm("@js-joda/core", "5.6.3"))
            implementation(npm("@js-joda/timezone", "2.22.0"))
            implementation(npm("@noble/ciphers", "2.4.0"))
            implementation(sphereonlib.software.amazon.app.platform.metro.impl)
            api(sphereonlib.dev.whyoleg.cryptography.provider.webcrypto)
        }
        findByName("jsTest")?.dependencies {
            implementation(sphereonlib.io.kotest.assertions.core)
            implementation(sphereonlib.io.kotest.framework.engine)
            implementation(sphereonlib.io.kotest.property)
            implementation(sphereonlib.io.ktor.client.core.js)
        }
        findByName("wasmJsMain")?.dependencies {
            implementation(sphereonlib.software.amazon.app.platform.metro.impl)
            api(sphereonlib.dev.whyoleg.cryptography.provider.webcrypto)
        }
        findByName("wasmJsTest")?.dependencies {
            implementation(sphereonlib.io.kotest.assertions.core)
            implementation(sphereonlib.io.kotest.property)
            implementation(sphereonlib.org.jetbrains.kotlinx.coroutines.test)
        }
        findByName("appleMain")?.dependencies {
            api(sphereonlib.io.ktor.client.darwin)
        }
    }
}

// Exclude kotest-framework-engine from wasmJs: it registers a duplicate 'startUnitTests'
// wasm export that conflicts with kotlin-test, causing module load failure (KT-72649).
configurations.matching { it.name.startsWith("wasmJs") && it.name.contains("Test") }.configureEach {
    exclude(group = "io.kotest", module = "kotest-framework-engine")
    exclude(group = "io.kotest", module = "kotest-framework-engine-wasm-js")
}

tasks.matching { it.name == "wasmJsNodeTest" }.configureEach {
    enabled = false
}

// Test coverage configuration
kover {
    reports {
        // Exclude test classes, generated code, and third-party DI code from coverage
        filters {
            excludes {
                classes("*Test", "*Test\$*", "*.testing.*", "*\$\$*")
                // Exclude Amazon lastmile inject library code (third-party DI infrastructure)
                classes("amazon.lastmile.inject.*", "software.amazon.lastmile.kotlin.inject.*")
                // Exclude generated component implementations
                classes("*.create\$*", "*\$Companion\$create\$*")
                classes("*\$\$InjectClass", "*\$\$InjectModule")
                // Exclude Kotlin interface default method implementations
                classes("**\$DefaultImpls", "**\$DefaultImpls\$*")
                // Exclude classes with unreachable defensive else branches
                // (IdentifierOptsOrResult only has 2 implementations: Managed and External)
                classes(
                    "com.sphereon.crypto.resolution.MultiIdentifierResolutionServiceImpl",
                    "com.sphereon.crypto.resolution.MultiIdentifierResolutionServiceImpl\$*",
                )
            }
        }

        total {
            verify {
                onCheck = false
                rule("Minimum line coverage") {
                    minBound(90)
                }
                rule("Minimum branch coverage") {
                    minBound(80)
                }
            }
        }
    }
}
