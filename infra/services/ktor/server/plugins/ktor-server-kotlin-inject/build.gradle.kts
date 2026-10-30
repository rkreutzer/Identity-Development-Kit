import com.sphereon.gradle.plugin.configureIosTargetsIfEnabled
import org.gradle.api.publish.maven.tasks.PublishToMavenLocal
import org.gradle.api.publish.maven.tasks.PublishToMavenRepository
import org.gradle.api.publish.plugins.PublishingPlugin

plugins {
    alias(sphereonplug.plugins.org.jetbrains.kotlin.multiplatform)
    alias(sphereonplug.plugins.com.vanniktech.maven.publish)
    alias(sphereonplug.plugins.org.jetbrains.kotlin.plugin.serialization)
    alias(sphereonplug.plugins.dev.zacsweers.metro)
    alias(sphereonplug.plugins.io.ktor.plugin)
}
metro {
}

kotlin {
    kotlin.applyDefaultHierarchyTemplate()

    jvm()
    run {
        val kmpTargets = (System.getProperty("kmp.targets") ?: "jvm").split(",").map { it.trim().lowercase() }
        if ("all" in kmpTargets || "js" in kmpTargets) {
            js {
                nodejs {
                    useEsModules()
                    binaries.library()
                    generateTypeScriptDefinitions()
                }
            }
        }
    }
    // configureIosTargetsIfEnabled()

    sourceSets {
        val commonMain by getting {
            dependencies {
                // Core IDK
                api(if (rootProject.findProperty("idk.consumeCoreAsArtifacts") == "true") "com.sphereon.idk:lib-core-api-public:$version" else project(":lib-core-api-public"))

                // kotlin-inject dependencies
                api(libs.bundles.app.platform.di)

                // Ktor Server (multiplatform)
                api(sphereonlib.io.ktor.server.core)

                // Kotlin reflection (multiplatform)
                implementation(sphereonlib.org.jetbrains.kotlin.reflect)

                // Coroutines (multiplatform)
                implementation(sphereonlib.org.jetbrains.kotlinx.coroutines.core)

                // UUID support (multiplatform)
                implementation(sphereonlib.org.jetbrains.kotlin.stdlib)
            }
        }

        val commonTest by getting {
            dependencies {
                implementation(sphereonlib.org.jetbrains.kotlin.test)
                implementation(sphereonlib.org.jetbrains.kotlinx.coroutines.test)
                implementation(if (rootProject.findProperty("idk.consumeCoreAsArtifacts") == "true") "com.sphereon.idk:lib-core-api-public:$version" else project(":lib-core-api-public"))
                implementation(if (rootProject.findProperty("idk.consumeCoreAsArtifacts") == "true") "com.sphereon.idk:lib-core-api-default:$version" else project(":lib-core-api-default"))
                implementation(if (rootProject.findProperty("idk.consumeInfrastructureAsArtifacts") == "true") "com.sphereon.idk:lib-data-link-http-client-impl:$version" else project(":lib-data-link-http-client-impl"))

                // Ktor testing (multiplatform core only)
                implementation(sphereonlib.io.ktor.server.test.host)
            }
        }

        val jvmMain by getting {
            dependencies {
                // JVM-specific ktor extensions (auth support — transitive so consumers get it)
                api(sphereonlib.io.ktor.server.auth)
                api(sphereonlib.io.ktor.server.auth.jwt)

                // YAML property source (standalone module)
                implementation(if (rootProject.findProperty("idk.consumeCoreAsArtifacts") == "true") "com.sphereon.idk:lib-conf-yaml:$version" else project(":lib-conf-yaml"))
            }
        }

        val jvmTest by getting {
            dependencies {
                // JVM-specific test dependencies
                implementation(sphereonlib.io.ktor.server.cio)
                implementation(sphereonlib.io.ktor.server.auth)
                implementation(sphereonlib.io.ktor.client.content.negotiation)

                // IDK test dependencies (JVM only as they may not have JS/Native targets)
                implementation(if (rootProject.findProperty("idk.consumeCoreAsArtifacts") == "true") "com.sphereon.idk:lib-core-api-public:$version" else project(":lib-core-api-public"))
                implementation(if (rootProject.findProperty("idk.consumeCoreAsArtifacts") == "true") "com.sphereon.idk:lib-core-api-default:$version" else project(":lib-core-api-default"))
                // Required for HttpClientFactory (used by JwksUrlExternalIdentifierResolutionService)
                implementation(if (rootProject.findProperty("idk.consumeInfrastructureAsArtifacts") == "true") "com.sphereon.idk:lib-data-link-http-client-impl:$version" else project(":lib-data-link-http-client-impl"))
            }
        }

        findByName("jsMain")?.dependencies {
            // JS-specific dependencies
            implementation("org.jetbrains.kotlin:kotlin-reflect:2.4.20")
        }

        findByName("jsTest")?.dependencies {
            // JS-specific test dependencies
            implementation(sphereonlib.org.jetbrains.kotlinx.coroutines.test.js)
            // Note: ktor-server-cio is not available for JS
            // JS tests use the test-host engine which is multiplatform
            implementation(sphereonlib.io.ktor.server.cio)
            implementation(sphereonlib.io.ktor.server.auth)
            implementation(sphereonlib.io.ktor.client.content.negotiation)

            // IDK test dependencies (JVM only as they may not have JS/Native targets)

            implementation(if (rootProject.findProperty("idk.consumeCoreAsArtifacts") == "true") "com.sphereon.idk:lib-core-api-public:$version" else project(":lib-core-api-public"))
            implementation(if (rootProject.findProperty("idk.consumeCoreAsArtifacts") == "true") "com.sphereon.idk:lib-core-api-default:$version" else project(":lib-core-api-default"))
        }
    }
}

// Repository publication retains the plugin compatibility restriction.
tasks.withType<PublishToMavenRepository>().configureEach {
    notCompatibleWithConfigurationCache("Publishing tasks are not compatible with configuration cache due to vanniktech maven publish plugin")
}
tasks.withType<PublishToMavenLocal>().configureEach {
    notCompatibleWithConfigurationCache("Publishing tasks are not compatible with configuration cache due to vanniktech maven publish plugin")
}

// Opt-in exact JVM CIO owner; absence preserves the ordinary public build.
apply(from = file("gradle/cio-runtime-verification.gradle.kts"))
