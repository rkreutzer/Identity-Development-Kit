import com.sphereon.gradle.plugin.configureIosTargetsIfEnabled
import com.sphereon.gradle.plugin.configureLinuxTargetIfEnabled
import com.sphereon.gradle.plugin.configureWasmJsTargetIfEnabled
import org.jetbrains.kotlin.gradle.dsl.JsModuleKind

plugins {
    // Fixes the multi-publish variant issue
    `maven-publish`
    alias(sphereonplug.plugins.org.jetbrains.kotlin.multiplatform)
    alias(sphereonplug.plugins.com.vanniktech.maven.publish)
    alias(sphereonplug.plugins.org.jetbrains.kotlin.plugin.serialization)
    alias(sphereonplug.plugins.dev.zacsweers.metro)
    alias(sphereonplug.plugins.org.jetbrains.kotlinx.atomicfu)
    alias(sphereonplug.plugins.com.sphereon.gradle.plugin.npm.publication)
    alias(sphereonplug.plugins.org.jetbrains.kotlinx.kover)
}
metro {
}

kotlin {
    // Allow internal API usage from xmlutil library (needed for DomWriter in tests)
    sourceSets.all {
        languageSettings {
            optIn("nl.adaptivity.xmlutil.XmlUtilInternal")
        }
    }

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
    configureIosTargetsIfEnabled()
    configureLinuxTargetIfEnabled()

    configureWasmJsTargetIfEnabled {
        nodejs()
        binaries.library()
        generateTypeScriptDefinitions()
    }

    sourceSets {
        val commonMain by getting {
            dependencies {
                api(projects.libCoreCompatAnnotations)
                // DefaultPropertySources extends atomicfu's SynchronizedObject: consumers compiling common
                // metadata (any non-JVM target) need atomicfu on their classpath. On the JVM it is a typealias.
                api(sphereonlib.org.jetbrains.kotlinx.atomicfu)
                implementation(sphereonlib.co.touchlab.skie.configuration.annotations)
                implementation(sphereonlib.com.michael.bull.kotlin.result.kotlin.result)
                // default deps are already injected by conventions plugin!
                api(sphereonlib.org.jetbrains.kotlinx.io.core)
                // Absorbed from lib-core-compat:
                api(sphereonlib.org.jetbrains.kotlinx.datetime)
                api(sphereonlib.io.matthewnelson.encoding.base64)
                api(sphereonlib.io.ktor.io)
                implementation(sphereonlib.io.github.pdvrieze.xmlutil.core)
                api(libs.bundles.app.platform.di)
                // Needed for the coroutine context
                api(sphereonlib.software.amazon.app.platform.metro.public)
                api(sphereonlib.software.amazon.app.platform.metro.impl)
                // HTTP client interfaces used across modules (implementations are supplied by host applications)
                api(sphereonlib.io.ktor.client.core)
                api(sphereonlib.io.ktor.client.content.negotiation)
                api(sphereonlib.io.ktor.client.logging)
                api(sphereonlib.io.ktor.serialization.kotlinx.json)
                // Konform validation — ValidationResult appears in the signature of
                // the ValidationExtensions API (toIdkResult/validate).
                api(sphereonlib.io.konform.konform)
            }
        }
        val commonTest by getting {
            dependencies {
                implementation(sphereonlib.org.jetbrains.kotlin.test)
                implementation(sphereonlib.org.jetbrains.kotlinx.coroutines.test)
                implementation(sphereonlib.software.amazon.app.platform.metro.impl)
            }
        }

        // Tests that depend on lib-core-api-default and lib-core-test
        // (shared by jvm, js, native tests; wasmJs has its own test source set)
        val nonWasmTest by creating {
            dependsOn(commonTest)
            dependencies {
                implementation(projects.libCoreApiDefault)
                implementation(projects.libCoreTest)
            }
        }
        val jvmTest by getting {
            dependsOn(nonWasmTest)
        }
        findByName("jsMain")?.dependencies {
            implementation(npm("@js-joda/timezone", "2.22.0"))
        }
        findByName("jsTest")?.apply {
            dependsOn(nonWasmTest)
            dependencies {
                implementation(sphereonlib.org.jetbrains.kotlinx.coroutines.core.js)
                implementation(sphereonlib.io.kotest.assertions.core)
                implementation(sphereonlib.io.kotest.framework.engine)
                implementation(sphereonlib.io.kotest.property)
                implementation(npm("jsdom", "~25.0.1"))
            }
        }
        findByName("nativeTest")?.dependsOn(nonWasmTest)
        findByName("wasmJsTest")?.dependencies {
            implementation(npm("jsdom", "~25.0.1"))
        }
    }
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
                // Exclude documentation/example code (not production code)
                classes("*Example", "*Example\$*")
                // Exclude Kotlin interface default method implementations (compiled as $DefaultImpls)
                // Using ** to match across package/class segments
                classes("**\$DefaultImpls", "**\$DefaultImpls\$*")
                // Exclude DI scope marker classes (abstract with private constructor, no testable behavior)
                classes("com.sphereon.di.session.SessionScope")
                // Exclude data classes marked with @CoverageExcludedDataClass (generated methods create excessive branches)
                annotatedBy("com.sphereon.core.api.conf.CoverageExcludedDataClass")
            }
        }

        total {
            verify {
                onCheck = false
                rule("Module minimum line coverage") {
                    minBound(80)
                }
            }
        }
    }
}
