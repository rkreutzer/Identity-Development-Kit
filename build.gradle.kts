@file:Suppress("UnstableApiUsage")

import org.jetbrains.kotlin.gradle.targets.js.testing.KotlinJsTest

val sphereonBuildProfile = (System.getenv("SPHEREON_BUILD_PROFILE")
    ?: System.getProperty("sphereon.build.profile"))?.trim()?.lowercase()

if (sphereonBuildProfile == "forms") {
    plugins.withType<org.jetbrains.kotlin.gradle.targets.js.nodejs.NodeJsRootPlugin> {
        extensions.configure<org.jetbrains.kotlin.gradle.targets.js.npm.NpmExtension> {
            lockFileDirectory.set(rootProject.layout.projectDirectory.dir("kotlin-js-store/forms"))
        }
    }
}

// Detect host architecture and OS
val osName = System.getProperty("os.name").lowercase()
val arch = System.getProperty("os.arch").lowercase()

// Only override Kotlin/Native home for Apple Silicon macOS
if (osName.contains("mac") && arch == "aarch64") {
    val konanDir = File(System.getProperty("user.home"), ".konan")
    val nativeDir = konanDir.listFiles()?.firstOrNull {
        it.isDirectory && it.name.startsWith("kotlin-native-prebuilt-macos-aarch64")
    }

    if (nativeDir != null) {
        logger.lifecycle("Using Kotlin/Native ARM64 toolchain at: ${nativeDir.absolutePath}")
        project.extensions.extraProperties["kotlin.native.home"] = nativeDir.absolutePath
    } else {
        logger.warn("No ARM64 Kotlin/Native toolchain found in ~/.konan — defaulting to automatic download.")
    }
} else {
    logger.lifecycle("Using default Kotlin/Native toolchain for $osName ($arch)")
}

apply(from = rootDir.resolve("gradle/idk-npm-runtime.gradle.kts"))

allprojects {
    group = "com.sphereon.idk"
    // version comes from platform-version.properties via settings.gradle.kts (gradle.beforeProject).

    // Workaround: Gradle's Kryo-based test output serializer corrupts binary result files when
    // Kotlin/Native tests produce output with non-standard characters (hex addresses, mangled symbols).
    // The allTests aggregate report task crashes reading these files. Individual test tasks (jvmTest,
    // linuxX64Test, etc.) still detect and report failures correctly.
    // See: https://github.com/gradle/gradle/issues/25268
    tasks.withType<org.gradle.api.tasks.testing.TestReport>().configureEach {
        if (name == "allTests") enabled = false
    }

    // Workaround: Kotlin 2.3.x npm-publish plugin registers wasmJs tasks whose mainFile provider
    // has no value, causing assembleWasmJsPackage to fail during task graph construction.
    // When wasmJs is NOT in kmp.targets, pre-register no-op tasks before the npm-publish plugin
    // can create its broken versions. When wasmJs IS active, the ConventionsPlugin workaround handles it.
    run {
        val kmpTargets = (System.getProperty("kmp.targets") ?: "jvm").split(",").map { it.trim().lowercase() }
        if ("all" !in kmpTargets && "wasmjs" !in kmpTargets && "wasm" !in kmpTargets) {
        }
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
                maven {
                    name = "sphereon-opensource"
                    val snapshotsUrl = "https://nexus.sphereon.com/repository/sphereon-opensource-snapshots/"
                    val releasesUrl = "https://nexus.sphereon.com/repository/sphereon-opensource-releases/"
                    url = uri(if (version.toString().contains("SNAPSHOT")) snapshotsUrl else releasesUrl)
                    credentials {
                        username = System.getenv("NEXUS_USERNAME")
                        password = System.getenv("NEXUS_PASSWORD")
                    }
                }
            }
        }
    }

}

plugins {
    alias(sphereonplug.plugins.com.sphereon.gradle.plugin.conventions) apply false
    alias(sphereonplug.plugins.com.sphereon.gradle.plugin.integration.tests) apply false
    alias(sphereonplug.plugins.com.sphereon.gradle.plugin.project.publication) apply false
    alias(sphereonplug.plugins.com.android.library) apply false
    alias(sphereonplug.plugins.com.android.application) apply false
    alias(sphereonplug.plugins.com.android.kotlin.multiplatform.library) apply false
    alias(sphereonplug.plugins.org.jetbrains.kotlin.multiplatform) apply false
    alias(sphereonplug.plugins.org.jetbrains.kotlin.jvm) apply false
    alias(sphereonplug.plugins.com.vanniktech.maven.publish) apply false
    alias(sphereonplug.plugins.org.jetbrains.kotlin.plugin.serialization) apply false
    alias(sphereonplug.plugins.io.kotest.io.kotest.gradle.plugin) apply false
    alias(sphereonplug.plugins.com.google.devtools.ksp.com.google.devtools.ksp.gradle.plugin) apply false
    alias(sphereonplug.plugins.dev.zacsweers.metro) apply false
    alias(sphereonplug.plugins.org.jetbrains.kotlin.android) apply false
    alias(sphereonplug.plugins.org.jetbrains.kotlin.npm.publish.org.jetbrains.kotlin.npm.publish.gradle.plugin) apply false
    alias(sphereonplug.plugins.org.jetbrains.kotlinx.atomicfu) apply false

    alias(sphereonplug.plugins.org.jetbrains.kotlin.plugin.compose) apply false
    alias(sphereonplug.plugins.org.jetbrains.compose) apply false
    alias(sphereonplug.plugins.org.jetbrains.compose.hot.reload) apply false
    alias(sphereonplug.plugins.io.ktor.plugin) apply false
    alias(sphereonplug.plugins.org.jlleitschuh.gradle.ktlint) apply false
    alias(sphereonplug.plugins.io.gitlab.arturbosch.detekt) apply false
    alias(sphereonplug.plugins.org.jetbrains.dokka)
}

subprojects {
    // Modules excluded from ktlint (generated code that gets added to source sets)
    val ktlintExcludedModules = setOf(
        "lib-crypto-kms-rest-api",             // OpenAPI generated sources
        "lib-crypto-kms-provider-digidentity", // OpenAPI generated sources
        "lib-crypto-key-persistence-sqlite",   // SQLDelight generated sources in commonMain source set
        "lib-crypto-kms-provider-aws",         // BuildKonfig generated sources in commonMain source set
        "lib-crypto-kms-provider-azure",       // BuildKonfig generated sources in commonMain source set
        "lib-data-store-okd-openapi",          // OpenAPI generated sources
    )

    if (!name.endsWith("-bom")) {
        apply(plugin = "com.sphereon.gradle.plugin.conventions")
        if (name !in ktlintExcludedModules) {
            apply(plugin = "org.jlleitschuh.gradle.ktlint")
            apply(plugin = "io.gitlab.arturbosch.detekt")
        }
    }

    plugins.withId("org.jlleitschuh.gradle.ktlint") {
        configure<org.jlleitschuh.gradle.ktlint.KtlintExtension> {
            version.set("1.8.0")
            outputToConsole.set(true)
            coloredOutput.set(true)
            filter {
                exclude { element -> element.file.absolutePath.replace('\\', '/').contains("/build/") }
            }
        }
    }

    plugins.withId("io.gitlab.arturbosch.detekt") {
        configure<io.gitlab.arturbosch.detekt.extensions.DetektExtension> {
            config.setFrom(rootProject.files("config/detekt/detekt.yml"))
            baseline = file("config/detekt/baseline.xml")
            buildUponDefaultConfig = false
            allRules = false
            parallel = true
            ignoreFailures = true
            autoCorrect = false
        }
        tasks.matching { it.name == "detektGenerateConfig" }.configureEach {
            enabled = false
        }
    }

    // kotlinx-io uses eval('require')('os') internally, which fails in ESM mode because
    // `require` is not available in ES modules. Provide require to ESM modules via a CJS preload shim.
    // See: https://github.com/Kotlin/kotlinx-io/issues/345
    val shimFile = rootProject.file("gradle-build-support/js/esm-require-shim.cjs")
    if (shimFile.exists()) {
        tasks.withType<KotlinJsTest>().configureEach {
            nodeJsArgs.add("--require")
            nodeJsArgs.add(shimFile.absolutePath)
        }
    }

    // xmlutil 0.90.1: duplicate function declarations in JS ESM output. 0.91.3 fixes this.
    // kotlinx-datetime: pin to the `0.7.1-0.6.x-compat` flavour. Vanilla
    // 0.7.1 moved `kotlinx.datetime.Instant` into `kotlin.time` (typealias)
    // and ships no class file on the runtime classpath. Kotlin Dataframe's
    // CSV / convert bytecode still calls the old class and throws
    // `NoClassDefFoundError: kotlinx/datetime/Instant` at ingest. The compat
    // build keeps both the legacy class and the new stdlib alias, so both
    // Dataframe and IDK call sites resolve. Force on every configuration so
    // a transitive 0.7.1 request loses the conflict (Gradle's version
    // ordering does NOT consider `0.7.1-0.6.x-compat` greater than `0.7.1`,
    // so without an explicit force the non-compat variant wins).
    configurations.configureEach {
        resolutionStrategy {
            force("io.github.pdvrieze.xmlutil:core:0.91.3")
            force("io.github.pdvrieze.xmlutil:serialization:0.91.3")
            force("org.jetbrains.kotlinx:kotlinx-datetime:0.7.1-0.6.x-compat")
            // Kotlin RC: force all Kotlin artifacts to match compiler version across all targets
            val kotlinVersion = extra["kotlin.version"] as String
            force("org.jetbrains.kotlin:kotlin-stdlib:$kotlinVersion")
            force("org.jetbrains.kotlin:kotlin-stdlib-common:$kotlinVersion")
            force("org.jetbrains.kotlin:kotlin-test:$kotlinVersion")
            force("org.jetbrains.kotlin:kotlin-test-common:$kotlinVersion")
            force("org.jetbrains.kotlin:kotlin-test-annotations-common:$kotlinVersion")
            force("org.jetbrains.kotlin:kotlin-test-junit:$kotlinVersion")
            force("org.jetbrains.kotlin:kotlin-test-junit5:$kotlinVersion")
            force("org.jetbrains.kotlin:kotlin-reflect:$kotlinVersion")
        }
    }
}

repositories {
    mavenCentral()
    google()
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
    maven("https://maven.pkg.jetbrains.space/public/p/compose/dev") {
        content {
            includeGroupAndSubgroups("org.jetbrains.compose")
            includeGroupAndSubgroups("org.jetbrains.kotlin")
            includeGroupAndSubgroups("org.jetbrains.kotlinx")
            includeGroupAndSubgroups("org.jetbrains.skiko")
        }
    }

    // Keep maven local at the end!!!!
    // https://slack-chats.kotlinlang.org/t/27045384/hi-there-i-have-a-very-annoying-internal-compiler-error-here
    mavenLocal {
        content {
            includeGroupAndSubgroups("com.sphereon")
        }
    }
}

// =============================================================================
// Aggregate Test Task for running all IDK tests from root
// =============================================================================
tasks.register("allTests") {
    group = "verification"
    description = "Run all IDK tests across all subprojects"
    dependsOn(provider { subprojects.mapNotNull { it.tasks.findByName("allTests") } })
}

// =============================================================================
// Aggregate NPM Tasks for publishing JS packages
// =============================================================================
tasks.register("publishAllNpmPackages") {
    group = "publishing"
    description = "Publish all IDK npm packages to npmjs"
    dependsOn(provider { subprojects.mapNotNull { it.tasks.findByName("publishJsPackageToNpmjsRegistry") } })
}

tasks.register("assembleAllNpmPackages") {
    group = "publishing"
    description = "Assemble all IDK npm packages (validate without publishing)"
    dependsOn(provider { subprojects.mapNotNull { it.tasks.findByName("assembleJsPackage") } })
}

// Force evaluation of every subproject so the deprecation task below can
// inspect their applied plugins. Only runs when the task is actually requested.
if (gradle.startParameter.taskNames.any { it.endsWith("listNpmPackageNames") }) {
    subprojects.forEach { evaluationDependsOn(it.path) }
}

tasks.register("listNpmPackageNames") {
    group = "publishing"
    description = "Write all @sphereon/idk-* npm package names this build publishes to build/npm-packages.txt"
    notCompatibleWithConfigurationCache("Enumerates subprojects at execution time")
    val outFile = layout.buildDirectory.file("npm-packages.txt")
    outputs.file(outFile)
    doLast {
        val names = subprojects
            .filter { it.plugins.hasPlugin("com.sphereon.gradle.plugin.npm-publication") }
            .map { "@sphereon/idk-${it.name}" }
            .sorted()
        val f = outFile.get().asFile
        f.parentFile.mkdirs()
        f.writeText(names.joinToString(separator = "\n", postfix = "\n"))
        logger.lifecycle("Wrote ${names.size} package name(s) to ${f.absolutePath}")
    }
}

// =============================================================================
// Aggregate ktlint Tasks
// =============================================================================
tasks.register("ktlintCheckAll") {
    group = "verification"
    description = "Run ktlint checks across all IDK subprojects"
    dependsOn(provider { subprojects.mapNotNull { it.tasks.findByName("ktlintCheck") } })
}

tasks.register("ktlintFormatAll") {
    group = "formatting"
    description = "Run ktlint format across all IDK subprojects"
    dependsOn(provider { subprojects.mapNotNull { it.tasks.findByName("ktlintFormat") } })
}

// =============================================================================
// Aggregate detekt Tasks
// =============================================================================
tasks.register("detektAll") {
    group = "verification"
    description = "Run detekt static analysis across all IDK subprojects"
    dependsOn(provider {
        subprojects.flatMap { sub ->
            sub.tasks.matching { it.name.startsWith("detekt") && !it.name.contains("Baseline") }
        }
    })
}

tasks.register("detektBaselineAll") {
    group = "verification"
    description = "Generate detekt baselines across all IDK subprojects"
    dependsOn(provider {
        subprojects.flatMap { sub ->
            sub.tasks.matching { it.name.startsWith("detekt") && it.name.contains("Baseline") }
        }
    })
}

// =============================================================================
// Dokka HTML Documentation
// =============================================================================

// Modules to exclude from Dokka due to classpath conflicts, generated code, or deprecated status
val dokkaExcludedModules = setOf(
    "tests-oid4vc-integration",           // oid4vci integration tests
    "lib-crypto-kms-rest-api",            // OpenAPI generated sources
    "lib-crypto-kms-provider-digidentity", // OpenAPI generated sources
    "lib-all",                            // Aggregator module, no actual code
    "lib-crypto-core",                    // Deprecated - placeholder only
    "lib-data-link-http-client"           // Deprecated - placeholder only
)

dokka {
    moduleName.set("Identity-Development-Kit (IDK)")
    moduleVersion.set(version.toString())

    dokkaPublications.html {
        outputDirectory.set(layout.buildDirectory.dir("dokka/html"))
        includes.from(rootDir.resolve("dokka/Module.md"))
    }

    pluginsConfiguration.html {
        footerMessage.set("© ${java.time.Year.now().value} Sphereon International B.V. | Creating Trust In A Digital World")
        customStyleSheets.from(rootDir.resolve("dokka/sphereon-styles.css"))
    }
}

// Apply Dokka plugin and aggregate dependencies only when a Dokka task is requested
val isDokkaRequested = gradle.startParameter.taskNames.any {
    it.contains("dokka", ignoreCase = true)
}
if (isDokkaRequested) {
    dependencies {
        // Aggregate documentation from all subprojects that have Dokka applied
        subprojects.forEach { subproject ->
            if (subproject.name !in dokkaExcludedModules) {
                subproject.plugins.withId("org.jetbrains.dokka") {
                    dokka(subproject)
                }
            }
        }
    }
    subprojects {
        if (name !in dokkaExcludedModules) {
            apply(plugin = "org.jetbrains.dokka")

            // Configure Dokka for each subproject with custom styles
            extensions.configure<org.jetbrains.dokka.gradle.DokkaExtension> {
                pluginsConfiguration.html {
                    customStyleSheets.from(rootDir.resolve("dokka/sphereon-styles.css"))
                    footerMessage.set("© ${java.time.Year.now().value} Sphereon International B.V. | Creating Trust In A Digital World")
                }

                val moduleMd = projectDir.resolve("dokka/module.md")
                if (moduleMd.exists()) {
                    dokkaPublications.html {
                        includes.from(moduleMd)
                    }
                }
            }

            // Ensure Dokka tasks run after copyGeneratedSources (for OpenAPI-generated code)
            afterEvaluate {
                tasks.matching { it.name.startsWith("dokka") }.configureEach {
                    tasks.findByName("copyGeneratedSources")?.let { mustRunAfter(it) }
                }
            }
        }
    }
}

abstract class VerifyWalletBoundaryTask : org.gradle.api.DefaultTask() {
    @get:org.gradle.api.tasks.Input
    abstract val violations: org.gradle.api.provider.ListProperty<String>

    // Text-scan leg, run alongside the dependency-edge check above. Uses the same plain per-line
    // regex/text scan over a fixed file collection as VerifyWalletKmsBoundaryTask (zero
    // allowlists), so the legacy single-orchestration Wallet facade (the `Wallet` interface +
    // `WalletImpl` + their `com.sphereon.wallet.Wallet` import) can never be reintroduced
    // anywhere in the wallet trees. Deliberately scans BOTH main and test sources (unlike the
    // KMS scan, which exempts tests) - there is no legitimate reason for this facade to reappear
    // anywhere, including test code.
    @get:org.gradle.api.tasks.InputFiles
    @get:org.gradle.api.tasks.PathSensitive(org.gradle.api.tasks.PathSensitivity.RELATIVE)
    abstract val orchestrationSourceFiles: org.gradle.api.file.ConfigurableFileCollection

    @get:org.gradle.api.tasks.Input
    abstract val orchestrationVdxRootPath: org.gradle.api.provider.Property<String>

    @org.gradle.api.tasks.TaskAction
    fun verify() {
        val found = violations.get()
        if (found.isNotEmpty()) {
            throw GradleException(
                "AGPL boundary violation: non-wallet modules depend on wallet modules:\n" +
                    found.joinToString("\n"),
            )
        }

        val vdxRoot = java.io.File(orchestrationVdxRootPath.get()).canonicalFile
        // Word-boundary regexes: `\b` after `WalletImpl`/`Wallet` fails to match when the name
        // continues with more word characters, so `WalletImplementationChoice` and
        // `WalletIdentityResolver` are NOT caught, but `class WalletImpl(`, `interface Wallet {`,
        // and `import com.sphereon.wallet.Wallet` (bare, or with a trailing ` as X` alias) are.
        val classWalletImpl = Regex("""\bclass\s+WalletImpl\b""")
        // \b (not a trailing char class) so a bodiless `interface Wallet` declaration is caught too.
        val interfaceWallet = Regex("""\binterface\s+Wallet\b""")
        val importWallet = Regex("""^\s*import\s+com\.sphereon\.wallet\.Wallet\b""")
        val permissiveSecurityDefault = Regex("""=\s*WalletSecurityGate\.allow\b""")
        val orchestrationViolations =
            orchestrationSourceFiles.files.flatMap { file ->
                val normalizedPath = file.canonicalPath.replace('\\', '/')
                val isMainSource = Regex("""/src/[^/]*Main/""").containsMatchIn(normalizedPath)
                file.readLines().mapIndexedNotNull { index, line ->
                    if (classWalletImpl.containsMatchIn(line) ||
                        interfaceWallet.containsMatchIn(line) ||
                        importWallet.containsMatchIn(line) ||
                        (isMainSource && permissiveSecurityDefault.containsMatchIn(line))
                    ) {
                        "${file.relativeTo(vdxRoot).invariantSeparatorsPath}:${index + 1}: ${line.trim()}"
                    } else {
                        null
                    }
                }
            }
        if (orchestrationViolations.isNotEmpty()) {
            throw GradleException(
                "Wallet orchestration/security boundary violation: the legacy Wallet/WalletImpl " +
                    "facade must not be reintroduced, and production constructors must not default " +
                    "to WalletSecurityGate.allow:\n" +
                    orchestrationViolations.joinToString("\n"),
            )
        }
    }
}

abstract class VerifyWalletKmsBoundaryTask : org.gradle.api.DefaultTask() {
    @get:org.gradle.api.tasks.InputFiles
    @get:org.gradle.api.tasks.PathSensitive(org.gradle.api.tasks.PathSensitivity.RELATIVE)
    abstract val sourceFiles: org.gradle.api.file.ConfigurableFileCollection

    @get:org.gradle.api.tasks.Input
    abstract val allowlistedFilePaths: org.gradle.api.provider.ListProperty<String>

    @get:org.gradle.api.tasks.Input
    abstract val vdxRootPath: org.gradle.api.provider.Property<String>

    @org.gradle.api.tasks.TaskAction
    fun verify() {
        val vdxRoot = java.io.File(vdxRootPath.get()).canonicalFile
        val allowlistedFiles = allowlistedFilePaths.get().map { java.io.File(it).canonicalFile }.toSet()
        // Match the whole com.sphereon.crypto.core.kms package (not a per-name alternation) plus the
        // whole com.sphereon.crypto.kms.provider package, so new names/providers are covered without
        // touching this task again.
        val forbiddenImport =
            Regex(
                """^\s*import\s+com\.sphereon\.crypto\.(core\.kms|kms\.provider)\..*""",
            )
        // Directory-exempt rule: any file under a lib/wallet/wscd/ module is a concrete WSCD
        // implementation by construction, so raw KMS imports there are in-boundary, not violations.
        // EDK remote wallet-unit WSCD adapters live under lib/wallet/unit/remote/.../wscd/ and
        // import KMS graph types only to replace them out of the consuming application graph.
        // allowlistedFilePaths is reserved for named, temporary leftovers only (see the task
        // registration below).
        fun isUnderWscdDirectory(file: java.io.File): Boolean {
            val path = file.canonicalFile.path.replace('\\', '/')
            return path.contains("/lib/wallet/wscd/") ||
                (path.contains("/lib/wallet/unit/remote/") && path.contains("/wscd/"))
        }
        // Flag the bare package text too, not only import lines - catches fully-qualified inline usage
        // (e.g. a type reference spelled out as com.sphereon.crypto.core.kms.KeyManagerService without
        // an import line) that the import-only regex above would miss.
        val forbiddenFqnText = "com.sphereon.crypto.core.kms."
        val forbiddenProviderFqnText = "com.sphereon.crypto.kms.provider."
        val violations =
            sourceFiles.files
                .filter { file -> file.canonicalFile !in allowlistedFiles }
                .filter { file -> !isUnderWscdDirectory(file) }
                .flatMap { file ->
                    file.readLines().mapIndexedNotNull { index, line ->
                        if (forbiddenImport.containsMatchIn(line) ||
                            line.contains("asKeyManagerServiceGraph") ||
                            line.contains(forbiddenFqnText) || line.contains(forbiddenProviderFqnText)
                        ) {
                            "${file.relativeTo(vdxRoot).invariantSeparatorsPath}:${index + 1}: ${line.trim()}"
                        } else {
                            null
                        }
                    }
                }
        if (violations.isNotEmpty()) {
            throw GradleException(
                "Wallet WSCA/WSCD boundary violation: raw KMS imports are only allowed in concrete WSCD implementations and tests:\n" +
                    violations.joinToString("\n"),
            )
        }
    }
}

abstract class VerifyWalletKmsDependencyRuleTask : org.gradle.api.DefaultTask() {
    @get:org.gradle.api.tasks.Input
    abstract val violations: org.gradle.api.provider.ListProperty<String>

    @org.gradle.api.tasks.TaskAction
    fun verify() {
        val found = violations.get()
        if (found.isNotEmpty()) {
            throw GradleException(
                "Wallet KMS dependency violation: only lib-wallet-wscd-* modules may depend on KMS providers:\n" +
                    found.joinToString("\n"),
            )
        }
    }
}

val verifyWalletBoundaryTask = tasks.register<VerifyWalletBoundaryTask>("verifyWalletBoundary") {
    group = "verification"
    description = "Fails if a project outside wallet depends on a project under wallet, or if the deleted single-orchestration Wallet facade reappears"
    violations.set(emptyList())
    // The standalone IDK owns reusable wallet libraries; product sources live in their owning repository.
    // Both *Main and *Test sources are included; test sources are not exempt here.
    val orchestrationVdxRoot = rootDir
    val orchestrationScanRoots =
        listOf(
            rootDir.resolve("wallet-lib/lib/wallet"),
        ).also { roots ->
            roots.forEach { check(it.isDirectory) { "Required wallet boundary source root is missing: $it" } }
        }
    orchestrationSourceFiles.from(
        orchestrationScanRoots.map { root ->
            fileTree(root) {
                include("**/*.kt")
                exclude("**/build/**")
            }
        },
    )
    orchestrationVdxRootPath.set(orchestrationVdxRoot.canonicalPath)
}

tasks.register<VerifyWalletKmsBoundaryTask>("verifyWalletKmsBoundary") {
    group = "verification"
    description = "Fails if wallet holder, interaction, or credential-store production code imports raw KMS APIs outside WSCD implementations"
    val vdxRoot = rootDir
    // Holder protocol adapters share the wallet WSCA/WSCD boundary. Issuer and verifier
    // implementations remain outside this scan because they legitimately use raw KMS APIs.
    val scanRoots =
        listOf(
            rootDir.resolve("wallet-lib/lib/wallet"),
            rootDir.resolve("protocols/lib/openid/oid4vci/holder"),
            rootDir.resolve("protocols/lib/openid/oid4vp/holder"),
        ).also { roots ->
            roots.forEach { check(it.isDirectory) { "Required wallet KMS boundary source root is missing: $it" } }
        }
    sourceFiles.from(
        scanRoots.map { root ->
            fileTree(root) {
                include("**/src/*Main/**/*.kt")
                // Lowercase jvm-only layout (e.g. lib/wallet/cli/src/main) - the *Main glob is
                // case-sensitive and would silently skip it.
                include("**/src/main/**/*.kt")
                exclude("**/build/**")
                exclude("**/src/*Test/**")
                exclude("**/src/test/**")
            }
        },
    )
    // No production code should need a temporary allowlist entry here (bootstraps must not import
    // KMS provider types directly). Kept as an empty, explicit list (not removed) so a future
    // genuinely-temporary leftover has an obvious place to register itself.
    allowlistedFilePaths.set(emptyList())
    vdxRootPath.set(vdxRoot.canonicalPath)
}

val verifyWalletKmsDependencyRuleTask =
    tasks.register<VerifyWalletKmsDependencyRuleTask>("verifyWalletKmsDependencyRule") {
        group = "verification"
        description = "Fails if a wallet module outside lib-wallet-wscd-* depends on a KMS provider module or the crypto core impl"
        violations.set(emptyList())
    }

/**
 * Enforces the greenfield presentation dependency direction:
 *
 *     headless public API -> presentation assembly -> presentation contracts -> renderer
 *
 * Contracts contain serializable state/intents and the Nav3 key marker only. The presenter is the
 * sole adapter from WalletApp/App Platform/Molecule into those contracts. Compose renders models;
 * it does not query WalletApp or holder implementations. This is intentionally a build-owned rule,
 * not a repository script that product builds can accidentally skip.
 */
abstract class VerifyWalletPresentationBoundaryTask : org.gradle.api.DefaultTask() {
    @get:org.gradle.api.tasks.Input
    abstract val dependencyViolations: org.gradle.api.provider.ListProperty<String>

    @get:org.gradle.api.tasks.InputFiles
    @get:org.gradle.api.tasks.PathSensitive(org.gradle.api.tasks.PathSensitivity.RELATIVE)
    abstract val sourceFiles: org.gradle.api.file.ConfigurableFileCollection

    @get:org.gradle.api.tasks.Input
    abstract val idkRootPath: org.gradle.api.provider.Property<String>

    @org.gradle.api.tasks.TaskAction
    fun verify() {
        val idkRoot = java.io.File(idkRootPath.get()).canonicalFile
        val violations = dependencyViolations.get().toMutableList()
        val importPattern = Regex("""^\s*import\s+([^\s]+)""")
        val walletImpl = Regex("""\b(class\s+WalletImpl|com\.sphereon\.wallet\.WalletImpl)\b""")
        val forbiddenCompatibilityDeclaration =
            Regex("""\b(?:data\s+class|sealed\s+class|class|interface|object|typealias)\s+\w*(?:Compat(?:ibility)?|Legacy)\w*\b""")
        val deprecatedDeclarationOrSuppression =
            Regex("""@(?:kotlin\.)?Deprecated\b|@Suppress\s*\(\s*[\"']DEPRECATION[\"']""")
        val bottomSheet = Regex("""\b(?:Modal|Standard)?BottomSheet\w*\b|\bbottom[ -]?sheet\b""", RegexOption.IGNORE_CASE)
        val onboardingSecretField =
            Regex("""\bval\s+(?:pin|secret|verifier|biometricToken)\s*:\s*[^,)=]+""", RegexOption.IGNORE_CASE)
        val onboardingRawSecretContainer = Regex("""\b(?:CharArray|ByteArray)\b""")
        val rawKms =
            listOf(
                "com.sphereon.crypto.core.kms.",
                "com.sphereon.crypto.kms.provider.",
                "asKeyManagerServiceGraph",
            )
        val rawNetworkClient =
            listOf(
                "io.ktor.",
                "HttpClient",
                "java.net.",
            )
        val forbiddenPlatformUi =
            listOf(
                "androidx.compose.ui.awt.SwingPanel",
                "androidx.compose.ui.viewinterop.AndroidView",
                "androidx.compose.ui.interop.UIKitView",
                "androidx.compose.ui.viewinterop.WebElementView",
                "java.awt.",
                "javax.swing.",
                "javafx.",
            )
        val credentialDetailRawImageLoader =
            listOf(
                "coil.",
                "io.kamel.",
                "AsyncImage",
                "SubcomposeAsyncImage",
                "rememberAsyncImagePainter",
                "ImageRequest",
                "KamelImage",
                "java.net.URL",
                "URL(",
            )
        val credentialDetailRendererBusinessLogic =
            listOf(
                "Json.decodeFromString",
                "Json.parseToJsonElement",
                "decodeFromString<",
                "kotlinx.serialization.json.",
                "Regex(",
                ".groupBy(",
                ".filter(",
                ".filter {",
                ".mapNotNull(",
                ".joinToString(",
                "·",
            )

        sourceFiles.files.sortedBy(java.io.File::getPath).forEach { file ->
            val path = file.canonicalFile.path.replace('\\', '/')
            val layer =
                when {
                    path.contains("/wallet/presentation/contracts/") -> "contracts"
                    path.contains("/wallet/presentation/presenter/") -> "presenter"
                    path.contains("/lib/wallet/interaction/presenter-contracts/") -> "interaction-contracts"
                    path.contains("/lib/wallet/interaction/presenter/") -> "interaction-presenter"
                    path.contains("/wallet/ui/compose/") -> "compose"
                    path.contains("/wallet/ui/navigation3/") -> "navigation3"
                    else -> return@forEach
                }
            val onboardingSource =
                file.name.contains("Onboarding", ignoreCase = true) ||
                    file.name.contains("PreProfileNavigation", ignoreCase = true)
            val onboardingSerializableLayer = layer == "contracts" || layer == "presenter" || layer == "navigation3"
            val credentialDetailRenderer = layer == "compose" && file.name.contains("CredentialDetail", ignoreCase = true)
            file.readLines().forEachIndexed { index, line ->
                val imported = importPattern.find(line)?.groupValues?.get(1)
                val commonViolation =
                    when {
                        rawKms.any(line::contains) -> "raw KMS access"
                        rawNetworkClient.any(line::contains) ->
                            "presentation layers must use profile-bound query/projection ports, not network clients"
                        walletImpl.containsMatchIn(line) -> "WalletImpl access"
                        forbiddenPlatformUi.any(line::contains) ->
                            "platform widget UI is forbidden; render with Compose Multiplatform"
                        bottomSheet.containsMatchIn(line) -> "bottom-sheet API"
                        deprecatedDeclarationOrSuppression.containsMatchIn(line) -> "deprecated declaration or suppressed deprecated usage"
                        forbiddenCompatibilityDeclaration.containsMatchIn(line) -> "compatibility or legacy declaration"
                        onboardingSource && onboardingSerializableLayer && onboardingRawSecretContainer.containsMatchIn(line) ->
                            "onboarding presentation state must not use raw secret containers"
                        onboardingSource && onboardingSerializableLayer && onboardingSecretField.containsMatchIn(line) ->
                            "onboarding presentation state must not declare serializable secret value fields"
                        imported?.contains(".compat.") == true || imported?.contains(".legacy.") == true -> "compatibility or legacy import"
                        imported?.startsWith("com.sphereon.enterprise.") == true ||
                            imported?.startsWith("com.sphereon.commercial.") == true ||
                            imported?.startsWith("com.sphereon.vdx.") == true ->
                            "commercial implementation import"
                        credentialDetailRenderer && credentialDetailRawImageLoader.any(line::contains) ->
                            "credential detail must not fetch external images; render only presenter-approved inline data"
                        credentialDetailRenderer && credentialDetailRendererBusinessLogic.any(line::contains) ->
                            "credential detail renderer must not parse claims or derive/filter activity"
                        else -> null
                    }
                val layerViolation =
                    when (layer) {
                        "contracts" ->
                            when {
                                imported == null -> null
                                imported.startsWith("com.sphereon.core.") ||
                                    imported.startsWith("kotlinx.io.") ||
                                    imported.startsWith("io.ktor.") ||
                                    imported.startsWith("com.sphereon.wallet.interaction.") &&
                                    !imported.startsWith("com.sphereon.wallet.interaction.presenter.contracts.") ->
                                    "wallet presentation contracts must depend only on serializable presentation contracts"
                                imported.startsWith("androidx.") ||
                                    imported.startsWith("org.jetbrains.compose.") ||
                                    imported.startsWith("software.amazon.app.platform.") ||
                                    imported.startsWith("com.sphereon.wallet.app.") ||
                                    imported.startsWith("com.sphereon.wallet.profile.") ||
                                    imported.startsWith("com.sphereon.wallet.ui.") ->
                                    "contracts must remain framework and wallet-runtime neutral"
                                else -> null
                            }
                        "interaction-contracts" ->
                            when {
                                imported == null ->
                                    when {
                                        Regex("""\bval\s+(?:state|authorizationUrl|accessToken|refreshToken|privateKey|credentialPayload)\s*:""")
                                            .containsMatchIn(line) -> "safe interaction contracts must not expose raw state or secret-bearing fields"
                                        else -> null
                                    }
                                imported.startsWith("com.sphereon.core.") ||
                                    imported.startsWith("kotlinx.io.") ||
                                    imported.startsWith("io.ktor.") ||
                                    imported.startsWith("com.sphereon.wallet.interaction.") &&
                                    !imported.startsWith("com.sphereon.wallet.interaction.presenter.contracts.") ->
                                    "interaction presenter contracts must contain presentation-owned types only"
                                imported.startsWith("androidx.") ||
                                    imported.startsWith("org.jetbrains.compose.") ||
                                    imported.startsWith("software.amazon.app.platform.") ||
                                    imported.startsWith("com.sphereon.wallet.app.") ||
                                    imported.startsWith("com.sphereon.wallet.profile.") ||
                                    imported.startsWith("com.sphereon.wallet.ui.") ||
                                    imported.contains(".impl.") ->
                                    "interaction presenter contracts must remain framework and runtime-implementation neutral"
                                else -> null
                            }
                        "presenter" ->
                            when {
                                imported == null -> null
                                imported.startsWith("androidx.compose.") && !imported.startsWith("androidx.compose.runtime.") ->
                                    "presenters may use Compose runtime for Molecule, not Compose UI"
                                imported.startsWith("androidx.navigation3.ui.") ||
                                    imported.startsWith("com.sphereon.wallet.ui.") ||
                                    imported.startsWith("com.sphereon.wallet.runner.") ||
                                    imported.contains(".impl.") ->
                                    "presenters must not depend on a renderer, runner, or implementation package"
                                else -> null
                            }
                        "interaction-presenter" ->
                            when {
                                imported == null -> null
                                imported.startsWith("androidx.compose.") && !imported.startsWith("androidx.compose.runtime.") ->
                                    "interaction presenters may use Compose runtime for Molecule, not Compose UI"
                                imported.startsWith("androidx.navigation3.") ||
                                    imported.startsWith("com.sphereon.wallet.ui.") ||
                                    imported.startsWith("com.sphereon.wallet.runner.") ||
                                    imported.contains(".impl.") ->
                                    "interaction presenters must not depend on navigation, renderers, runners, or implementations"
                                else -> null
                            }
                        "compose" ->
                            when {
                                imported == null -> null
                                imported.startsWith("com.sphereon.wallet.app.") ||
                                    imported.startsWith("com.sphereon.wallet.profile.") ||
                                    imported.startsWith("com.sphereon.wallet.credential.") ||
                                imported.startsWith("com.sphereon.wallet.interaction.") &&
                                    !imported.startsWith("com.sphereon.wallet.interaction.presenter.contracts.") ||
                                    imported.startsWith("com.sphereon.wallet.runner.") ||
                                    imported.startsWith("com.sphereon.wallet.presentation.presenter.") ||
                                    imported.startsWith("androidx.navigation3.") ||
                                    imported.contains(".impl.") ->
                                    "Compose must render presentation APIs instead of accessing wallet/runtime implementations"
                                else -> null
                            }
                        "navigation3" ->
                            when {
                                imported == null -> null
                                imported.startsWith("com.sphereon.wallet.app.") ||
                                    imported.startsWith("com.sphereon.wallet.profile.") ||
                                    imported.startsWith("com.sphereon.wallet.credential.") ||
                                    imported.startsWith("com.sphereon.wallet.interaction.") ||
                                    imported.startsWith("com.sphereon.wallet.runner.") ||
                                    imported.contains(".impl.") ->
                                    "Navigation 3 adapter must consume presentation state and renderer APIs only"
                                else -> null
                            }
                        else -> null
                    }
                listOfNotNull(commonViolation, layerViolation).distinct().forEach { reason ->
                    violations +=
                        "${file.relativeTo(idkRoot).invariantSeparatorsPath}:${index + 1}: $reason: ${line.trim()}"
                }
            }
        }

        sourceFiles.files.sortedBy(java.io.File::getPath).forEach { file ->
            file.readLines().forEachIndexed { index, line ->
                if (line.contains("WalletCredentialDetailTab")) {
                    violations +=
                        "${file.relativeTo(idkRoot).invariantSeparatorsPath}:${index + 1}: " +
                            "obsolete detail-tab route is forbidden; credential detail is one process-style screen: ${line.trim()}"
                }
            }
        }

        if (violations.isNotEmpty()) {
            throw GradleException(
                "Wallet presentation boundary violation. Keep contracts framework-neutral, adapt " +
                    "WalletApp only in presenters, and keep renderers free of wallet business logic:\n" +
                    violations.distinct().joinToString("\n"),
            )
        }
    }
}

val verifyWalletPresentationBoundaryTask =
    tasks.register<VerifyWalletPresentationBoundaryTask>("verifyWalletPresentationBoundary") {
        group = "verification"
        description = "Enforces greenfield wallet contracts/presenter/renderer dependency and source boundaries"
        dependencyViolations.set(emptyList())
        val presentationRoots =
            listOf(
                rootDir.resolve("wallet-lib/lib/wallet/interaction/presenter-contracts"),
                rootDir.resolve("wallet-lib/lib/wallet/interaction/presenter"),
            ).also { roots ->
                roots.forEach { check(it.isDirectory) { "Required wallet presentation source root is missing: $it" } }
            }
        sourceFiles.from(
            presentationRoots.map { root ->
                fileTree(root) {
                    include("**/*.kt")
                    exclude("**/build/**")
                }
            },
        )
        idkRootPath.set(rootDir.canonicalPath)
    }

abstract class VerifyWalletReferenceBoundaryTask : org.gradle.api.DefaultTask() {
    @get:org.gradle.api.tasks.Input
    abstract val dependencyViolations: org.gradle.api.provider.ListProperty<String>

    @get:org.gradle.api.tasks.InputFiles
    @get:org.gradle.api.tasks.PathSensitive(org.gradle.api.tasks.PathSensitivity.RELATIVE)
    abstract val sourceFiles: org.gradle.api.file.ConfigurableFileCollection

    @get:org.gradle.api.tasks.Input
    abstract val idkRootPath: org.gradle.api.provider.Property<String>

    @org.gradle.api.tasks.TaskAction
    fun verify() {
        val banned =
            Regex(
                """@(?:kotlin\.)?Deprecated\b|\bTODO\b|\bFIXME\b|\b(?:Modal|Standard)?BottomSheet\w*\b|\bbottom[ -]?sheet\b|\b(?:Legacy|Compat(?:ibility)?)\w*\b""",
                RegexOption.IGNORE_CASE,
            )
        val forbiddenImports =
            listOf(
                "com.sphereon.crypto.core.kms.",
                "com.sphereon.crypto.kms.provider.",
                "com.sphereon.wallet.runner.",
                "com.sphereon.enterprise.",
                "com.sphereon.commercial.",
                "com.sphereon.vdx.",
                "io.ktor.",
                "java.net.",
                "HttpClient",
            )
        val forbiddenPlatformUi =
            listOf(
                "androidx.compose.ui.awt.SwingPanel",
                "androidx.compose.ui.viewinterop.AndroidView",
                "androidx.compose.ui.interop.UIKitView",
                "androidx.compose.ui.viewinterop.WebElementView",
                "java.awt.",
                "javax.swing.",
                "javafx.",
            )
        val localOnlyForbidden =
            listOf(
                "com.sphereon.enterprise.",
                "com.sphereon.commercial.",
                "com.sphereon.vdx.",
                "com.sphereon.wallet.interaction.remote.",
                "com.sphereon.wallet.unit.remote.",
                "com.sphereon.data.store.blob.http.",
                "ManagedProfileProvisioningRequest",
                "ManagedProfileBinding",
                "WalletBackendRouteRef",
                "DefaultPrincipalMapPropertySource",
                "DefaultAppMapPropertySource",
            )
        val localOnboardingNetworkForbidden =
            listOf(
                "io.ktor.",
                "HttpClient",
                "com.sphereon.wallet.interaction.remote.",
                "com.sphereon.wallet.unit.remote.",
                "RemoteConfiguration",
                "RemoteBranding",
                "RemoteProvisioning",
                "ManagedProfileProvisioningRequest",
            )
        val violations = dependencyViolations.get().toMutableList()
        val idkRoot = java.io.File(idkRootPath.get()).canonicalFile
        sourceFiles.files.sortedBy(java.io.File::getPath).forEach { file ->
            val normalizedPath = file.canonicalFile.path.replace('\\', '/')
            val localCompositionSource =
                normalizedPath.contains("/wallet/reference/local/src/") ||
                    normalizedPath.contains("/wallet/reference/node/src/") ||
                    normalizedPath.contains("/wallet/reference/wasm/src/") ||
                    normalizedPath.endsWith("/wallet/app/impl/src/commonMain/kotlin/com/sphereon/wallet/app/WalletAppBootstrap.kt") ||
                    normalizedPath.contains("/wallet/app/impl/src/commonMain/kotlin/com/sphereon/wallet/app/LocalWallet") ||
                    normalizedPath.contains("/wallet/app/impl/src/commonMain/kotlin/com/sphereon/wallet/app/AppLocalWallet") ||
                    normalizedPath.contains("/wallet/app/impl/src/commonMain/kotlin/com/sphereon/wallet/app/di/WalletProductAppGraph.kt") ||
                    normalizedPath.endsWith("/wallet/profile/impl/src/commonMain/kotlin/com/sphereon/wallet/profile/impl/LocalProfileProvisioner.kt")
            val localOnboardingSource =
                normalizedPath.endsWith("/wallet/app/impl/src/commonMain/kotlin/com/sphereon/wallet/app/LocalWalletApplicationServices.kt") ||
                    normalizedPath.endsWith("/wallet/presentation/presenter/src/commonMain/kotlin/com/sphereon/wallet/presentation/presenter/WalletLocalOnboardingPresenter.kt") ||
                    normalizedPath.endsWith("/wallet/reference/app/src/commonMain/kotlin/com/sphereon/wallet/reference/app/WalletReferenceBootstrapCoordinator.kt") ||
                    normalizedPath.contains("/wallet/reference/local/src/") ||
                    normalizedPath.contains("/wallet/reference/node/src/") ||
                    normalizedPath.contains("/wallet/reference/wasm/src/")
            file.readLines().forEachIndexed { index, line ->
                val reason =
                    when {
                        forbiddenImports.any(line::contains) -> "forbidden runtime import"
                        forbiddenPlatformUi.any(line::contains) -> "platform widget UI is forbidden; render with Compose Multiplatform"
                        localCompositionSource && localOnlyForbidden.any(line::contains) ->
                            "local reference must not resolve managed/backend routes or remote wallet clients"
                        localOnboardingSource && localOnboardingNetworkForbidden.any(line::contains) ->
                            "local onboarding must remain local-authority-only and must not resolve VDX or remote clients"
                        banned.containsMatchIn(line) -> "greenfield source violation"
                        else -> null
                    }
                if (reason != null) violations += "${file.relativeTo(idkRoot).invariantSeparatorsPath}:${index + 1}: $reason: ${line.trim()}"
            }
        }
        if (violations.isNotEmpty()) {
            throw GradleException(
                "Wallet reference boundary violation. Keep the product on public WalletApp/presenter/UI " +
                "contracts and confine local runtime assembly to native or Node local-authority adapters:\n" +
                    violations.distinct().joinToString("\n"),
            )
        }
    }
}

val verifyWalletReferenceBoundaryTask =
    tasks.register<VerifyWalletReferenceBoundaryTask>("verifyWalletReferenceBoundary") {
        group = "verification"
        description = "Enforces the greenfield AGPL reference app and local composition-root boundary"
        dependencyViolations.set(emptyList())
        sourceFiles.from(
            fileTree(rootDir.resolve("wallet-lib/lib/wallet/party/local/src").also { check(it.isDirectory) { "Required wallet party local source root is missing: $it" } }) {
                include("*Main/**/*.kt")
                exclude("**/build/**")
            },
            fileTree(rootDir.resolve("wallet-lib/lib/wallet/party").also { check(it.isDirectory) { "Required wallet party source root is missing: $it" } }) {
                include("**/src/*Main/**/*.kt")
                exclude("**/build/**")
            },
        )
        idkRootPath.set(rootDir.canonicalPath)
    }

val verifyWalletProductUiTargetContractTask =
    tasks.register("verifyWalletProductUiTargetContract") {
        group = "verification"
        description = "Requires JVM, classic JS, WasmJS, Android, and iOS across reusable IDK UI modules"
        notCompatibleWithConfigurationCache("Reads wallet Gradle scripts from the source tree")
        val productBuilds =
            linkedMapOf(
                "lib-conf-theme-compose" to rootDir.resolve("platform/lib/conf/theme/compose/build.gradle.kts"),
                "lib-ui-compose" to rootDir.resolve("platform/lib/ui/compose/build.gradle.kts"),
            )
        inputs.files(productBuilds.values)
        doLast {
            val requiredDeclarations =
                linkedMapOf(
                    "JVM" to Regex("""\bjvm\s*\("""),
                    "classic JS" to Regex("""\bconfigureJsTargetIfEnabled\s*\{"""),
                    "WasmJS" to Regex("""\bconfigureWasmJsTargetIfEnabled\s*\{"""),
                    "Android target" to Regex("""\bandroid\s*\{"""),
                    "Android KMP plugin" to Regex("""plugins\.com\.android\.kotlin\.multiplatform\.library"""),
                    "iOS device and simulator" to Regex("""\bconfigureIosTargetsIfEnabled\s*\("""),
                )
            val violations =
                productBuilds.flatMap { (module, buildFile) ->
                    val source = buildFile.readText()
                    requiredDeclarations
                        .filterValues { declaration -> !declaration.containsMatchIn(source) }
                        .keys
                        .map { missing -> "$module: missing $missing" } +
                        if (Regex("""\bandroidLibrary\s*\{""").containsMatchIn(source)) {
                            listOf("$module: deprecated androidLibrary target DSL is forbidden; use android")
                        } else {
                            emptyList()
                        }
                }
            if (violations.isNotEmpty()) {
                throw GradleException(
                    "Wallet product UI target contract regression. Every product layer must " +
                        "declare JVM, classic JS, WasmJS, Android, iOS device, and iOS simulator targets:\n" +
                        violations.joinToString("\n"),
                )
            }


        }
    }

val verifyWalletUiDependencyVersionsTask =
    tasks.register("verifyWalletUiDependencyVersions") {
        group = "verification"
        description = "Pins the supported Compose Multiplatform and Navigation 3 versions for every wallet target"
        notCompatibleWithConfigurationCache("Reads owning build scripts and resolved catalog metadata")
        val catalogs = rootProject.extensions.getByType<org.gradle.api.artifacts.VersionCatalogsExtension>()
        val pluginCatalog = catalogs.named("sphereonplug")
        val libraryCatalog = catalogs.named("sphereonlib")
        val pluginVersions = pluginCatalog.pluginAliases.associate { alias ->
            val plugin = pluginCatalog.findPlugin(alias).get().get()
            plugin.pluginId to plugin.version.requiredVersion
        }
        val libraryVersions = libraryCatalog.libraryAliases.associate { alias ->
            val library = libraryCatalog.findLibrary(alias).get().get()
            "${library.module.group}:${library.module.name}" to library.versionConstraint.requiredVersion
        }
        val reusableUiBuilds =
            listOf("platform/lib/conf/theme", "platform/lib/ui", "wallet-lib/lib/wallet")
                .onEach { path -> check(rootDir.resolve(path).isDirectory) { "Required reusable UI source root is missing: $path" } }
                .flatMap { path -> fileTree(rootDir.resolve(path)) { include("**/build.gradle.kts") }.files }
                .sortedBy(java.io.File::getPath)
        inputs.properties(mapOf("resolvedPluginVersions" to pluginVersions, "resolvedLibraryVersions" to libraryVersions))
        inputs.files(reusableUiBuilds)
        val sourceRoot = rootDir
        doLast {
            val violations = mutableListOf<String>()
            if (pluginVersions["org.jetbrains.compose"] != "1.11.1") {
                violations += "Compose Multiplatform plugin must be 1.11.1"
            }
            listOf(
                "org.jetbrains.compose.runtime:runtime:1.11.1",
                "org.jetbrains.compose.foundation:foundation:1.11.1",
                "org.jetbrains.compose.ui:ui:1.11.1",
                "org.jetbrains.compose.ui:ui-test:1.11.1",
                "org.jetbrains.compose.ui:ui-tooling-preview:1.11.1",
                "org.jetbrains.compose.material3:material3:1.11.0-alpha07",
                "org.jetbrains.compose.material:material-icons-extended:1.7.3",
            ).filterNot { coordinate ->
                val components = coordinate.split(':')
                libraryVersions["${components[0]}:${components[1]}"] == components[2]
            }.forEach { coordinate ->
                violations += "shared library BOM is missing $coordinate"
            }
            if (libraryVersions["androidx.navigation3:navigation3-runtime"] != "1.1.4") {
                violations += "canonical Navigation 3 runtime must be 1.1.4"
            }
            if (libraryVersions["org.jetbrains.androidx.navigation3:navigation3-ui"] != "1.1.1") {
                violations += "Wasm/iOS-capable JetBrains Compose Multiplatform Navigation 3 UI port must be 1.1.1"
            }
            reusableUiBuilds.forEach { buildFile ->
                val text = buildFile.readText()
                if (Regex("""\b(?:api|implementation)\s*\(\s*compose\.""").containsMatchIn(text)) {
                    violations +=
                        "${buildFile.relativeTo(sourceRoot).invariantSeparatorsPath}: deprecated compose.* dependency accessor is forbidden; use sphereonlib"
                }
                if (text.contains("1.10.3") || text.contains("material3:material3:1.9.0")) {
                    violations += "${buildFile.relativeTo(sourceRoot).invariantSeparatorsPath}: stale hard-coded Compose version"
                }
                if (text.contains("\"androidx.navigation3:navigation3-ui")) {
                    violations +=
                        "${buildFile.relativeTo(sourceRoot).invariantSeparatorsPath}: AndroidX Navigation 3 UI has no JS/WasmJS/iOS variants; use the JetBrains Compose Multiplatform port"
                }
            }
            if (violations.isNotEmpty()) throw GradleException("Wallet UI dependency version violation:\n${violations.joinToString("\n")}")
        }
    }

gradle.projectsEvaluated {
    val allowed =
        mapOf(
            "wallet-reference-app" to
                setOf(
                    "wallet-app-public",
                    "wallet-presentation",
                    "wallet-presentation-molecule",
                    "wallet-reference-compose",
                    "wallet-ui-compose",
                    "wallet-ui-navigation3",
                ),
            "wallet-reference-compose" to setOf("wallet-presentation-contracts", "wallet-presentation-molecule", "wallet-ui-compose", "wallet-ui-navigation3"),
            "wallet-reference-local" to setOf("wallet-reference-app", "wallet-app-impl", "lib-wallet-wsca-impl"),
            "wallet-reference-node" to
                setOf(
                    "wallet-app-impl",
                    "wallet-presentation",
                ),
            "wallet-reference-wasm" to
                setOf(
                    "wallet-reference-compose",
                    "wallet-ui-compose",
                ),
        )
    verifyWalletReferenceBoundaryTask.configure {
        val forbiddenLocalRuntimeDependencies =
            listOf(
                "enterprise-wallet",
                "commercial-wallet",
                "wallet-interaction-remote",
                "wallet-unit-remote",
                "wallet-provider-remote",
                "data-store-blob-client-http",
            )
        val localIsolationViolations = mutableListOf<String>()
        val visited = mutableSetOf<String>()

        fun visitProductionDependencies(project: org.gradle.api.Project) {
            if (!visited.add(project.path)) return
            project.configurations
                .filter { configuration ->
                    configuration.name.contains("Main", ignoreCase = true) &&
                        !configuration.name.contains("Test", ignoreCase = true)
                }.forEach { configuration ->
                    configuration.dependencies.forEach { dependency ->
                        val dependencyName = dependency.name.lowercase()
                        if (forbiddenLocalRuntimeDependencies.any(dependencyName::contains)) {
                            localIsolationViolations +=
                            "local reference production graph reaches ${dependency.group}:${dependency.name} via ${project.path}:${configuration.name}"
                        }
                        if (dependency is org.gradle.api.artifacts.ProjectDependency) {
                            rootProject.findProject(dependency.path)?.let(::visitProductionDependencies)
                        }
                    }
                }
        }
        rootProject.findProject(":wallet-reference-local")?.let(::visitProductionDependencies)
        rootProject.findProject(":wallet-reference-node")?.let(::visitProductionDependencies)
        rootProject.findProject(":wallet-reference-wasm")?.let(::visitProductionDependencies)

        dependencyViolations.set(
            allowed.flatMap { (projectName, permitted) ->
                val project = rootProject.findProject(":$projectName") ?: return@flatMap emptyList()
                project.configurations
                    .filterNot { configuration -> configuration.name.contains("Test", ignoreCase = true) }
                    .flatMap { configuration ->
                        configuration.dependencies
                            .filterIsInstance<org.gradle.api.artifacts.ProjectDependency>()
                            .mapNotNull { dependency ->
                                val dependencyName = dependency.path.removePrefix(":")
                                if (dependencyName !in permitted) {
                                    ":$projectName (${configuration.name}) -> ${dependency.path}; allowed=$permitted"
                                } else {
                                    null
                                }
                            }
                    }
            } + localIsolationViolations,
        )
    }
}

gradle.projectsEvaluated {
    val allowedProjectDependencies =
        mapOf(
            "wallet-presentation-contracts" to setOf("lib-wallet-interaction-presenter-contracts"),
            "lib-wallet-interaction-presenter-contracts" to emptySet(),
            "lib-wallet-interaction-presenter" to
                setOf(
                    "lib-wallet-interaction-public",
                    "lib-wallet-interaction-presenter-contracts",
                ),
            "wallet-presentation" to
                setOf(
                    "wallet-presentation-contracts",
                    "wallet-app-public",
                    "lib-wallet-interaction-presenter",
                    "lib-catalog-public",
                ),
            "wallet-presentation-molecule" to setOf("wallet-presentation-contracts"),
            "wallet-ui-compose" to
                setOf(
                    "wallet-presentation-contracts",
                    "lib-conf-theme-compose",
                    "lib-ui-compose",
                ),
            "wallet-ui-navigation3" to
                setOf(
                    "wallet-presentation-contracts",
                    "wallet-presentation-molecule",
                    "wallet-ui-compose",
                ),
        )
    verifyWalletPresentationBoundaryTask.configure {
        dependencyViolations.set(
            allowedProjectDependencies.flatMap { (projectName, allowedDependencies) ->
                val project = rootProject.findProject(":$projectName") ?: return@flatMap emptyList()
                project.configurations.flatMap { configuration ->
                    configuration.dependencies
                        .filterIsInstance<org.gradle.api.artifacts.ProjectDependency>()
                        .mapNotNull { dependency ->
                            val dependencyName = dependency.path.removePrefix(":")
                            if (dependencyName !in allowedDependencies) {
                                ":$projectName (${configuration.name}) -> ${dependency.path}; allowed=$allowedDependencies"
                            } else {
                                null
                            }
                        }
                }
            },
        )
    }
}

gradle.projectsEvaluated {
    // Only lib-wallet-wscd-* modules may depend on KMS provider modules or the crypto core impl; every
    // other wallet module - the lib/wallet tree AND the wallet PRODUCT tree (wallet/app, wallet/runner,
    // wallet/cli, wallet/profile) - must reach KMS through WSCA/WSCD instead of touching it directly.
    //
    // lib/openid is scanned too, but for the KMS PROVIDER prefixes only, not lib-crypto-core-impl:
    // lib-openid-oid4vci-holder-impl has a real, justified `api` dependency on lib-crypto-core-impl
    // for non-KMS JOSE/JWT impl classes, and the issuer/verifier modules (server-side, outside the
    // WSCA/WSCD boundary) legitimately use it for their own signing. lib-crypto-core-impl bundles
    // JOSE and KMS bindings in one module, so a bare module-name check cannot tell those apart -
    // the import-level verifyWalletKmsBoundary scan (extended to the oid4vci/oid4vp holder
    // submodules) draws that finer line.
    val kmsProviderPrefixes = listOf("lib-crypto-kms-provider-", "lib-crypto-kms-")
    val kmsRestrictedPrefixes = kmsProviderPrefixes + "lib-crypto-core-impl"
    val libWalletRoot = rootDir.toPath().resolve("wallet-lib/lib/wallet").toAbsolutePath().normalize()
    val libOpenidRoot = rootDir.toPath().resolve("protocols/lib/openid").toAbsolutePath().normalize()
    // lib-wallet-impl's jvmMain must not depend on lib-crypto-kms-provider-software directly - KMS
    // registration goes through the WSCA/WSCD boundary (SoftwareKmsProviderRegistrar,
    // lib-wallet-wscd-software). Its commonMain must not directly depend on lib-crypto-core-impl
    // either; that dependency stays transitively compile-visible via lib-openid-oid4vci-holder-impl's
    // own api dependency on it, needed there for non-KMS JOSE/crypto impl classes. Kept as an empty,
    // explicit set (not removed) so a future genuinely-temporary leftover has an obvious place to
    // register itself.
    val kmsDependencyAllowlist = emptySet<String>()
    // Test configurations are exempt: the boundary philosophy (see verifyWalletKmsBoundary's
    // message) allows raw KMS use in concrete WSCD implementations AND tests.
    fun isTestConfiguration(name: String): Boolean = name.contains("test", ignoreCase = true)
    verifyWalletKmsDependencyRuleTask.configure {
        violations.set(
            rootProject.subprojects
                .mapNotNull { p ->
                    val projectPath = p.projectDir.toPath().toAbsolutePath().normalize()
                    val restricted =
                        when {
                            p.name.startsWith("lib-wallet-wscd-") -> null
                            projectPath.startsWith(libWalletRoot) -> kmsRestrictedPrefixes
                            projectPath.startsWith(libOpenidRoot) -> kmsProviderPrefixes
                            else -> null
                        }
                    restricted?.let { p to it }
                }
                .flatMap { (p, restricted) ->
                    p.configurations
                        .filterNot { isTestConfiguration(it.name) }
                        .flatMap { cfg ->
                            cfg.dependencies
                                .filterIsInstance<org.gradle.api.artifacts.ProjectDependency>()
                                .mapNotNull { dep ->
                                    val depName = dep.path.removePrefix(":")
                                    if (restricted.any { depName.startsWith(it) || depName == it }) {
                                        "${p.path} (${cfg.name}) -> ${dep.path}"
                                    } else {
                                        null
                                    }
                                }
                        }
                }
                .filterNot { it in kmsDependencyAllowlist },
        )
    }
}

object ApplicationTenantSourceGuard {
    val ownedSourceRoots = listOf("core", "infra", "identity-security", "protocols", "platform", "wallet-lib", "lib", "examples", "tests")
    const val canonicalPath = "core/lib/core/api/public/src/commonMain/kotlin/com/sphereon/core/api/conf/ApplicationTenantConstants.kt"
    val prunedDirectories = setOf("build", ".git", ".gradle", ".claude", "node_modules")
    val testSourceSet = Regex("""/src/[A-Za-z0-9]*[Tt]est[A-Za-z0-9]*/""")

    fun violations(repositoryRoot: java.io.File): List<String> {
        val root = repositoryRoot.canonicalFile
        val canonical = java.io.File(root, canonicalPath).canonicalFile
        require(canonical.isFile) { "Shared application tenant constants missing: $canonicalPath" }
        val constants = canonical.readText()
        require(Regex("""const\s+val\s+KEY_APPLICATION_TENANT_ID(?:\s*:\s*String)?\s*=\s*["]application\.tenant\.id["]""").containsMatchIn(constants)) {
            "Canonical application tenant key must remain application.tenant.id"
        }
        require(Regex("""const\s+val\s+DEFAULT_APPLICATION_TENANT_ID(?:\s*:\s*String)?\s*=\s*["]platform["]""").containsMatchIn(constants)) {
            "Canonical application tenant default must remain platform"
        }
        val found = mutableListOf<String>()
        ownedSourceRoots.forEach { relativeRoot ->
            val ownedRoot = java.io.File(root, relativeRoot).canonicalFile
            require(ownedRoot.isDirectory && ownedRoot.toPath().startsWith(root.toPath())) { "Missing owned production source root: $relativeRoot" }
            val sources = ownedRoot.walkTopDown()
                .onEnter { directory -> directory.name !in prunedDirectories && !testSourceSet.containsMatchIn(directory.invariantSeparatorsPath + "/") }
                .filter { file -> file.isFile && file.name.endsWith(".kt") && !testSourceSet.containsMatchIn(file.invariantSeparatorsPath) }
                .toList()
            require(sources.isNotEmpty()) { "Empty owned production source root: $relativeRoot" }
            sources.forEach { file ->
                require(file.canonicalFile.toPath().startsWith(root.toPath())) { "Production source escapes owning repository: $file" }
                if (file.canonicalFile != canonical) {
                    val content = file.readText()
                    val relative = file.relativeTo(root).invariantSeparatorsPath
                    if (content.contains("\"application.tenant.id\"")) found += "$relative declares the application tenant key instead of importing KEY_APPLICATION_TENANT_ID"
                    if (content.contains("const val DEFAULT_APPLICATION_TENANT_ID")) found += "$relative declares an application tenant default instead of importing DEFAULT_APPLICATION_TENANT_ID"
                }
            }
        }
        return found
    }
}

abstract class VerifyApplicationTenantConstantsTask : org.gradle.api.DefaultTask() {
    @get:org.gradle.api.tasks.Internal
    abstract val repositoryRoot: org.gradle.api.file.DirectoryProperty

    @get:org.gradle.api.tasks.InputFiles
    @get:org.gradle.api.tasks.PathSensitive(org.gradle.api.tasks.PathSensitivity.RELATIVE)
    abstract val productionSources: org.gradle.api.file.ConfigurableFileCollection

    @org.gradle.api.tasks.TaskAction
    fun verify() {
        val violations = ApplicationTenantSourceGuard.violations(repositoryRoot.get().asFile)
        if (violations.isNotEmpty()) throw org.gradle.api.GradleException(violations.joinToString("\n"))
    }
}

val verifyApplicationTenantConstantsTask = tasks.register<VerifyApplicationTenantConstantsTask>("verifyApplicationTenantConstants") {
    group = "verification"
    description = "Requires all owned production sources to use the canonical application tenant key and default"
    repositoryRoot.set(layout.projectDirectory)
    productionSources.from(ApplicationTenantSourceGuard.ownedSourceRoots.map { sourceRoot ->
        fileTree(sourceRoot) {
            include("**/*.kt")
            ApplicationTenantSourceGuard.prunedDirectories.forEach { exclude("**/$it/**") }
            exclude("**/src/*Test*/**", "**/src/*test*/**")
        }
    })
}

val rootCheckTask =
    tasks.findByName("check")?.let { tasks.named("check") }
        ?: tasks.register("check") {
            group = "verification"
            description = "Runs verification tasks for the root project"
        }

rootCheckTask.configure {
    dependsOn(verifyApplicationTenantConstantsTask)
    dependsOn(verifyWalletBoundaryTask)
    dependsOn("verifyWalletKmsBoundary")
    dependsOn(verifyWalletKmsDependencyRuleTask)
    dependsOn(verifyWalletPresentationBoundaryTask)
    dependsOn(verifyWalletReferenceBoundaryTask)
    dependsOn(verifyWalletProductUiTargetContractTask)
    dependsOn(verifyWalletUiDependencyVersionsTask)
}
