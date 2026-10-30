rootProject.name = "idk-platform-pack"
enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")

// IDK checkout root (platform -> ..)
val idkRoot = settings.rootDir.resolve("..").canonicalFile

fun includeLocal(name: String, relativeFromPack: String) {
    val workspaceSelection = System.getenv("WORKSPACE_SOURCE_MODULES")
    if (workspaceSelection != null && name !in workspaceSelection.split(",").map { it.trim() }.filter { it.isNotEmpty() }) return
    include(":" + name)
    project(":" + name).projectDir = settings.rootDir.resolve(relativeFromPack)
}

pluginManagement {
    val idkRootDir = settings.rootDir.resolve("..").normalize()
    val platformVersionFile = idkRootDir.resolve("platform-version.properties")
    require(platformVersionFile.isFile) { "Missing " + platformVersionFile.absolutePath }
    val platformProps = java.util.Properties().apply {
        platformVersionFile.reader(Charsets.UTF_8).use { load(it) }
    }
    val gbsVersionProperty = platformProps.getProperty("gbsVersion")!!.trim()
    val platformVersionProperty = platformProps.getProperty("platformVersion")!!.trim()
    settings.extra["gbsVersion"] = gbsVersionProperty
    settings.extra["platformVersion"] = platformVersionProperty

    val worktreeMavenRepo = System.getenv("WORKTREE_MAVEN_REPO")?.trim()?.takeIf { it.isNotEmpty() }


    settings.extra["gbsUseLocalGradleBuildSupport"] = false

    // The fork publishes its implementation; resolve it without a plugin marker.
    resolutionStrategy {
        eachPlugin {
            if (requested.id.id == "software.amazon.app.platform") {
                useModule("software.amazon.app.platform:gradle-plugin:${requested.version}")
            }
        }
    }

    repositories {
        // Local SPH App Platform / Metro plugin markers (not always mirrored on Nexus yet).
        mavenLocal()
        if (worktreeMavenRepo != null) {
            exclusiveContent {
                forRepository {
                    maven {
                        name = "worktree"
                        url = uri(worktreeMavenRepo)
                    }
                }
                filter {
                    includeGroupByRegex(
                        if (System.getenv("WORKSPACE_TOOL_MAVEN_REPO") == null) "com\\.sphereon(\\..+)?"
                        else "com\\.sphereon(?!\\.gradle(?:\\.|$))(\\..+)?"
                    )
                }
            }
        }
        google {
            mavenContent {
                includeGroupAndSubgroups("androidx")
                includeGroupAndSubgroups("com.android")
                includeGroupAndSubgroups("com.google")
            }
        }
        mavenCentral()
        gradlePluginPortal()
        maven {
            url = uri("https://oss.sonatype.org/content/repositories/snapshots/")
            mavenContent { snapshotsOnly() }
        }
        maven {
            url = uri("https://aws.oss.sonatype.org/content/repositories/snapshots/")
            mavenContent { snapshotsOnly() }
            content { includeGroupAndSubgroups("software.amazon") }
        }
        maven {
            url = uri("https://nexus.sphereon.com/repository/sphereon-opensource-snapshots/")
            mavenContent { snapshotsOnly() }
            content {
                includeGroupAndSubgroups("com.sphereon")
                includeGroupAndSubgroups("software.amazon")
            }
        }
        maven {
            url = uri("https://nexus.sphereon.com/repository/sphereon-opensource-releases/")
            mavenContent { releasesOnly() }
            content {
                includeGroupAndSubgroups("com.sphereon")
                includeGroupAndSubgroups("software.amazon")
            }
        }
        maven("https://maven.pkg.jetbrains.space/public/p/compose/dev") {
            content {
                includeGroupAndSubgroups("org.jetbrains.compose")
                includeGroupAndSubgroups("org.jetbrains.kotlin")
                includeGroupAndSubgroups("org.jetbrains.kotlinx")
                includeGroupAndSubgroups("org.jetbrains.skiko")
            }
        }
    }
    plugins {
        id("com.sphereon.gradle.toml-catalog") version gbsVersionProperty
        id("app.cash.sqldelight") version "2.3.2"
    }
}

plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}

val platformVersion = settings.extra["platformVersion"] as String
val gbsVersion = settings.extra["gbsVersion"] as String

gradle.beforeProject {
    version = platformVersion
    group = "com.sphereon.idk"
    extra["platformVersion"] = platformVersion
    extra["gbsVersion"] = gbsVersion
    extra["idk.consumeWalletAsArtifacts"] = "true"
    extra["idk.consumeCoreAsArtifacts"] = "true"
    extra["idk.consumeProtocolsAsArtifacts"] = "true"
    extra["idk.consumeIdentitySecurityAsArtifacts"] = "true"
    extra["idk.consumeInfrastructureAsArtifacts"] = "true"
}

dependencyResolutionManagement {
    repositories {
        val worktreeMavenRepo = System.getenv("WORKTREE_MAVEN_REPO")?.trim()?.takeIf { it.isNotEmpty() }

        if (worktreeMavenRepo != null) {
            exclusiveContent {
                forRepository {
                    maven {
                        name = "worktree"
                        url = uri(worktreeMavenRepo)
                    }
                }
                filter {
                    includeGroupByRegex(
                        if (System.getenv("WORKSPACE_TOOL_MAVEN_REPO") == null) "com\\.sphereon(\\..+)?"
                        else "com\\.sphereon(?!\\.gradle(?:\\.|$))(\\..+)?"
                    )
                }
            }
        }
        google {
            mavenContent {
                includeGroupAndSubgroups("androidx")
                includeGroupAndSubgroups("com.android")
                includeGroupAndSubgroups("com.google")
            }
        }
        mavenCentral()
        gradlePluginPortal()
        maven {
            url = uri("https://oss.sonatype.org/content/repositories/snapshots/")
            mavenContent { snapshotsOnly() }
        }
        maven {
            url = uri("https://aws.oss.sonatype.org/content/repositories/snapshots/")
            mavenContent { snapshotsOnly() }
            content { includeGroupAndSubgroups("software.amazon") }
        }
        maven {
            url = uri("https://nexus.sphereon.com/repository/sphereon-opensource-snapshots/")
            mavenContent { snapshotsOnly() }
            content {
                includeGroupAndSubgroups("com.sphereon")
                includeGroupAndSubgroups("software.amazon")
            }
        }
        maven {
            url = uri("https://nexus.sphereon.com/repository/sphereon-opensource-releases/")
            mavenContent { releasesOnly() }
            content {
                includeGroupAndSubgroups("com.sphereon")
                includeGroupAndSubgroups("software.amazon")
            }
        }
        maven("https://maven.pkg.jetbrains.space/public/p/compose/dev") {
            content {
                includeGroupAndSubgroups("org.jetbrains.compose")
                includeGroupAndSubgroups("org.jetbrains.kotlin")
                includeGroupAndSubgroups("org.jetbrains.kotlinx")
                includeGroupAndSubgroups("org.jetbrains.skiko")
            }
        }
        mavenLocal {
            content { includeGroupAndSubgroups("com.sphereon") }
        }
    }
    versionCatalogs {
        create("sphereonplug") {
            from("com.sphereon.gradle:gradle-plugin-bom:$gbsVersion@toml" as String)
        }
        create("sphereonlib") {
            from("com.sphereon.gradle:library-bom:$gbsVersion@toml" as String)
        }
        create("libs") {
            from(files(idkRoot.resolve("gradle/libs.versions.toml")))
        }
        create("awssdk") {
            from("aws.sdk.kotlin:version-catalog:1.6.107" as String)
        }
    }
}

println("==> idk-platform-pack: GBS from worktree-m2; platformVersion=$platformVersion; platform (catalog/theme/ui/attribute/credential-definition)")

// Platform modules (catalog, theme, UI, attribute, credential-definition).
includeLocal("idk-bom", "versions/idk-bom")
includeLocal("lib-catalog-impl", "lib/catalog/impl")
includeLocal("lib-identity-resolution-catalog", "lib/identity/resolution/catalog")
includeLocal("lib-oauth2-server-authorization-theme", "lib/oauth2/server/authorization-theme")
includeLocal("lib-catalog-persistence-api", "lib/catalog/persistence/api")
includeLocal("lib-catalog-persistence-memory", "lib/catalog/persistence/memory")
includeLocal("lib-catalog-persistence-sqlite", "lib/catalog/persistence/sqlite")
includeLocal("lib-catalog-public", "lib/catalog/public")
includeLocal("lib-catalog-ts11-public", "lib/catalog/ts11-public")
includeLocal("lib-conf-theme-client", "lib/conf/theme/client")
includeLocal("lib-conf-theme-compose", "lib/conf/theme/compose")
includeLocal("lib-conf-theme-core-impl", "lib/conf/theme/core/impl")
includeLocal("lib-conf-theme-web", "lib/conf/theme/web")
includeLocal("lib-data-credential-definition-impl", "lib/data/credential-definition/impl")
includeLocal("lib-data-credential-definition-public", "lib/data/credential-definition/public")
includeLocal("lib-data-credential-definition-rest", "lib/data/credential-definition/rest")
includeLocal("lib-ui-compose", "lib/ui/compose")
includeLocal("lib-ui-compose-blob-adapter", "lib/ui/compose-blob-adapter")

includeLocal("lib-catalog-eu-public", "lib/catalog/eu-public")
includeLocal("lib-catalog-eu-impl", "lib/catalog/eu-impl")

// Kotlin's npm resolver looks up source dependencies in this build's direct
// includes. Outer composite siblings alone do not provide that lookup. Keep
// artifact mode unless a web target and its source dependency packs are selected.
val webSourceTargets = (System.getProperty("kmp.targets") ?: "jvm")
    .split(",").map { it.trim().lowercase() }
val selectedSourcePacks = System.getenv("IDK_LOCAL_PACKS").orEmpty()
    .split(",").map { it.trim() }.filter { it.isNotEmpty() }.toSet()
val selectedSourceModules = System.getenv("WORKSPACE_SOURCE_MODULES")
    ?.split(",")?.map { it.trim() }?.filter { it.isNotEmpty() }?.toSet()
if (webSourceTargets.any { it in setOf("js", "wasmjs", "all") }) {
    listOf("core", "identity-security", "infra", "protocols")
        .filter { it in selectedSourcePacks }
        .forEach { pack ->
            val packRoot = idkRoot.resolve(pack)
            val packSettings = packRoot.resolve("settings.gradle.kts")
            require(packSettings.isFile) { "Missing pack settings: ${packSettings.absolutePath}" }
            val modulePattern = Regex("""include(?:Local|Mapped)\s*\(\s*"([^"]+)"\s*,\s*"[^"]+"\s*\)""")
            val modules = packSettings.readLines()
                .filter { line ->
                    val trimmed = line.trim()
                    !trimmed.startsWith("//") && !trimmed.startsWith("/*") && !trimmed.startsWith("*")
                }
                .mapNotNull { modulePattern.find(it)?.groupValues?.get(1) }
                .distinct()
            require(modules.isNotEmpty()) { "No pack modules in ${packSettings.absolutePath}" }
            includeBuild(packRoot) {
                name = "idk-$pack"
                dependencySubstitution {
                    // Match includeLocal's workspace filter so excluded projects
                    // are never substituted with an unavailable project path.
                    modules.filter { selectedSourceModules == null || it in selectedSourceModules }
                        .forEach { moduleName ->
                            substitute(module("com.sphereon.idk:$moduleName"))
                                .using(project(":$moduleName"))
                        }
                }
            }
        }
}
