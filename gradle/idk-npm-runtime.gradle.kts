import javax.inject.Inject

// Makes every published `@sphereon/idk-*` JS package self-contained.
//
// Kotlin/JS names the module `@sphereon/idk-<module>`, so it links the IDK modules into a `@sphereon`
// directory and every other module (kotlin-stdlib, kotlinx-*, ktor-*, cryptography-*, ...) next to it. The
// IDK modules import those as `../kotlin-kotlin-stdlib.mjs`. The npm-publish plugin only packs the
// `@sphereon` directory, so an installed package resolved `../x.mjs` to `node_modules/@sphereon/x.mjs`, which
// no package provides, and failed at import time.
//
// This script ships those runtime modules inside the package, under `idk-runtime/`, and points the
// imports at them. Apply it from a pack's root build script (it configures that pack's subprojects).
//
// Scripts applied with `apply(from = ...)` do not see classes from the `plugins {}` block, so this only
// touches Gradle API types and reaches the npm-publish extension reflectively.

val idkNpmRuntimeDir = "idk-runtime"

@CacheableTask
abstract class StageNpmRuntime : DefaultTask() {
    @get:Inject
    abstract val fs: FileSystemOperations

    @get:Inject
    abstract val objects: ObjectFactory

    // The directories the npm-publish plugin would have packed: the scoped module directory and resources.
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val packageFiles: ConfigurableFileCollection

    @get:Input
    abstract val runtimeDir: Property<String>

    @get:OutputDirectory
    abstract val stageDir: DirectoryProperty

    private fun scopeDir() = packageFiles.files.firstOrNull { it.name.startsWith("@") }

    private fun excludedFromRuntime(scope: File) = listOf("${scope.name}/**", "**/*.d.mts", "**/*.d.ts", "package.json")

    // Resolved lazily: the package directories are compiler outputs and cannot be queried while the task graph is built.
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val runtimeFiles: ConfigurableFileCollection

    fun runtimeTree(locations: Set<FileSystemLocation>): FileCollection {
        val scope = locations.map { it.asFile }.firstOrNull { it.name.startsWith("@") }
        val tree = objects.fileTree()
        if (scope?.parentFile != null) tree.from(scope.parentFile).exclude(excludedFromRuntime(scope))
        return tree
    }

    @TaskAction
    fun stage() {
        val scope = scopeDir()
        val libDir = scope?.parentFile
        val stage = stageDir.get().asFile
        val runtime = runtimeDir.get()

        fs.sync {
            from(packageFiles)
            if (scope != null && libDir != null) {
                from(libDir) {
                    exclude(excludedFromRuntime(scope))
                    into(runtime)
                }
            }
            into(stage)
        }
        if (libDir == null) return

        val parentImport = Regex("""(\b(?:from|import)\s*)(['"])\.\./""")
        val relativeImport = Regex("""\b(?:from|import)\s*['"](\.{1,2}/[^'"]+)['"]""")
        val unresolved = sortedSetOf<String>()
        stage.listFiles { file -> file.isFile && file.extension == "mjs" }.orEmpty().forEach { file ->
            val original = file.readText()
            val rewritten = original.replace(parentImport) { "${it.groupValues[1]}${it.groupValues[2]}./$runtime/" }
            if (rewritten != original) file.writeText(rewritten)
            relativeImport.findAll(rewritten)
                .map { it.groupValues[1] }
                .filterNot { file.parentFile.resolve(it).normalize().isFile }
                .forEach { unresolved += "${file.name} -> $it" }
        }
        // An import that resolves to nothing is what made the packages unusable, so never publish one.
        if (unresolved.isNotEmpty()) {
            throw GradleException(
                "The npm package for $path imports modules it does not contain:\n" +
                    unresolved.joinToString("\n") { "  $it" },
            )
        }
    }
}

subprojects {
    plugins.withId("org.jetbrains.kotlin.npm-publish") {
        val npmPublish = extensions.getByName("npmPublish")
        @Suppress("UNCHECKED_CAST")
        val packages = npmPublish.javaClass.getMethod("getPackages").invoke(npmPublish) as NamedDomainObjectContainer<Any>

        packages.configureEach(
            Action<Any> {
                val pkg = this
                if ((pkg as Named).name != "js") return@Action
                val files = pkg.javaClass.getMethod("getFiles").invoke(pkg) as ConfigurableFileCollection
                val original = files.from.toList()
                val stageTask = tasks.register("stageJsNpmRuntime", StageNpmRuntime::class.java) {
                    description = "Stages the JS package contents together with the runtime modules they import"
                    packageFiles.from(original)
                    runtimeFiles.from(packageFiles.elements.map { runtimeTree(it) })
                    runtimeDir.set(idkNpmRuntimeDir)
                    stageDir.set(layout.buildDirectory.dir("npm-staging/js"))
                }
                files.setFrom(stageTask.flatMap { it.stageDir })
            },
        )
    }
}
