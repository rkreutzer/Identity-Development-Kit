plugins {
    // Root-only: Sphereon wrapper for Autonomous Apps (GBS README; do not apply in included builds)
    alias(libs.plugins.sphereon.dependency.analysis)
    alias(sphereonplug.plugins.com.sphereon.gradle.plugin.conventions) apply false
    alias(sphereonplug.plugins.com.sphereon.gradle.plugin.npm.publication) apply false
    alias(sphereonplug.plugins.com.sphereon.gradle.plugin.project.publication) apply false
    alias(sphereonplug.plugins.com.sphereon.gradle.plugin.integration.tests) apply false
    alias(sphereonplug.plugins.com.android.library) apply false
    alias(sphereonplug.plugins.com.android.application) apply false
    alias(sphereonplug.plugins.com.android.kotlin.multiplatform.library) apply false
    alias(sphereonplug.plugins.org.jetbrains.kotlin.multiplatform) apply false
    alias(sphereonplug.plugins.org.jetbrains.kotlin.jvm) apply false
    alias(sphereonplug.plugins.org.jetbrains.kotlin.android) apply false
    alias(sphereonplug.plugins.org.jetbrains.kotlin.plugin.serialization) apply false
    alias(sphereonplug.plugins.com.vanniktech.maven.publish) apply false
    alias(sphereonplug.plugins.com.google.devtools.ksp.com.google.devtools.ksp.gradle.plugin) apply false
    alias(sphereonplug.plugins.dev.zacsweers.metro) apply false
    alias(sphereonplug.plugins.software.amazon.app.platform) apply false
    alias(sphereonplug.plugins.org.jetbrains.kotlinx.atomicfu) apply false
    alias(sphereonplug.plugins.org.jetbrains.kotlin.plugin.compose) apply false
    alias(sphereonplug.plugins.org.jetbrains.compose) apply false
    alias(sphereonplug.plugins.org.jetbrains.compose.hot.reload) apply false
    alias(sphereonplug.plugins.io.ktor.plugin) apply false
    alias(sphereonplug.plugins.org.jlleitschuh.gradle.ktlint) apply false
    alias(sphereonplug.plugins.io.gitlab.arturbosch.detekt) apply false
    alias(sphereonplug.plugins.io.kotest.io.kotest.gradle.plugin) apply false
    alias(sphereonplug.plugins.org.jetbrains.kotlinx.kover) apply false
    alias(sphereonplug.plugins.org.openapi.generator) apply false
    alias(sphereonplug.plugins.com.codingfeline.buildkonfig) apply false
    alias(sphereonplug.plugins.org.jetbrains.kotlin.npm.publish.org.jetbrains.kotlin.npm.publish.gradle.plugin) apply false
}

apply(from = rootDir.resolve("../gradle/idk-npm-runtime.gradle.kts"))

allprojects {
    group = "com.sphereon.idk"
}

subprojects {
    if (!name.endsWith("-bom")) {
        apply(plugin = "com.sphereon.gradle.plugin.conventions")
        // Pack-local analysis: Autonomous Apps needs the plugin on each analyzed project.
        apply(plugin = "com.sphereon.gradle.plugin.dependency-analysis")
    }

    plugins.withType<MavenPublishPlugin> {
        configure<PublishingExtension> {
            repositories {
                val worktreeMavenRepo = System.getenv("WORKTREE_MAVEN_REPO")?.trim()?.takeIf { it.isNotEmpty() }
                if (worktreeMavenRepo != null) {
                    maven {
                        name = "worktree"
                        url = uri(worktreeMavenRepo)
                    }
                }
            }
        }
    }
}
