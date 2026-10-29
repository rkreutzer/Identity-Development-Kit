/*
 * © 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package com.sphereon.crypto.kms.keystore.software

import com.sphereon.crypto.core.kms.KeyStoreLoaderOpts
import com.sphereon.crypto.core.kms.KeyStoreUtils
import com.sphereon.crypto.core.kms.model.PredefinedKeyStoreTypes
import io.ktor.utils.io.jvm.javaio.toInputStream
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.security.KeyStore

/**
 * Interface defining how to load a [KeyStore] from provided options.
 */
interface KeyStoreLoader {
    /**
     * Load and return a [KeyStore] based on the given [opts].
     *
     * @param opts options describing type, source, and password for the KeyStore
     */
    suspend fun load(opts: KeyStoreLoaderOpts): KeyStore
}

/**
 * Optional platform directory provider to resolve placeholders in file paths without reflection.
 *
 * Usage on Android (in Application.onCreate):
 *   PlatformDirProvider.set(object : PlatformDirProvider.Provider {
 *       override fun filesDir(): File = applicationContext.filesDir
 *       override fun cacheDir(): File = applicationContext.cacheDir
 *       override fun contextDir(name: String): File =
 *           applicationContext.getDir(name, android.content.Context.MODE_PRIVATE)
 *       override fun tempDir(): File = applicationContext.cacheDir
 *   })
 *
 * A sensible JVM-default provider is installed by default, so registration is optional on pure JVM.
 */
object PlatformDirProvider {
    interface Provider {
        fun filesDir(): File

        fun cacheDir(): File

        fun contextDir(name: String): File

        fun tempDir(): File
    }

    @Volatile
    private var provider: Provider = DefaultJvmProvider

    fun set(p: Provider) {
        provider = p
    }

    internal fun get(): Provider = provider

    /**
     * Default JVM provider:
     * - filesDir:   ~/.keystore
     * - cacheDir:   java.io.tmpdir
     * - contextDir: ~/.keystore/<name>
     * - tempDir:    java.io.tmpdir
     */
    private object DefaultJvmProvider : Provider {
        private val userHomeDir: File =
            System.getProperty("user.home")?.let(::File) ?: File(".")
        private val defaultFilesDir = File(userHomeDir, ".keystore")
        private val defaultTempDir = File(System.getProperty("java.io.tmpdir") ?: ".")

        override fun filesDir(): File = defaultFilesDir

        override fun cacheDir(): File = defaultTempDir

        override fun contextDir(name: String): File = File(defaultFilesDir, name)

        override fun tempDir(): File = defaultTempDir
    }
}

/**
 * Utilities to interpret platform-specific placeholders in file paths.
 *
 * Supported placeholders (only when PlatformDirProvider is present; it always is via JVM default):
 * - {filesDir}/...              -> filesDir
 * - {cacheDir}/...              -> cacheDir
 * - {contextDir}/...            -> contextDir("")
 * - {contextDir:dirName}/...    -> contextDir("dirName")
 * - {tempDir}/...               -> tempDir
 */
object PathPlaceholderInterpreter {
    private const val FILES_DIR_PREFIX = "{filesDir}"
    private const val CACHE_DIR_PREFIX = "{cacheDir}"
    private const val TEMP_DIR_PREFIX = "{tempDir}"
    private const val CONTEXT_DIR_PREFIX = "{contextDir}"
    private const val CONTEXT_DIR_WITH_NAME_PREFIX = "{contextDir:"
    private const val PATH_SEPARATOR = "/"
    private const val CLOSING_BRACE = '}'

    fun resolve(path: String): File? {
        val prov = PlatformDirProvider.get()

        // Handle {filesDir} pattern
        if (path.startsWith(FILES_DIR_PREFIX)) {
            val base = prov.filesDir()
            return when {
                path == FILES_DIR_PREFIX -> {
                    base
                }

                path.startsWith("$FILES_DIR_PREFIX$PATH_SEPARATOR") -> {
                    File(base, path.substring(FILES_DIR_PREFIX.length + 1))
                }

                else -> {
                    null
                }
            }
        } else if (path.startsWith(CACHE_DIR_PREFIX)) {
            // Handle {cacheDir} pattern
            val base = prov.cacheDir()
            return when {
                path == CACHE_DIR_PREFIX -> {
                    base
                }

                path.startsWith("$CACHE_DIR_PREFIX$PATH_SEPARATOR") -> {
                    File(base, path.substring(CACHE_DIR_PREFIX.length + 1))
                }

                else -> {
                    null
                }
            }
        } else if (path.startsWith(TEMP_DIR_PREFIX)) {
            // Handle {tempDir} pattern
            val base = prov.tempDir()
            return when {
                path == TEMP_DIR_PREFIX -> {
                    base
                }

                path.startsWith("$TEMP_DIR_PREFIX$PATH_SEPARATOR") -> {
                    File(base, path.substring(TEMP_DIR_PREFIX.length + 1))
                }

                else -> {
                    null
                }
            }
        } else if (path.startsWith(CONTEXT_DIR_PREFIX) && !path.startsWith(CONTEXT_DIR_WITH_NAME_PREFIX)) {
            // Handle {contextDir} pattern (without directory name)
            val base = prov.contextDir("")
            return when {
                path == CONTEXT_DIR_PREFIX -> {
                    base
                }

                path.startsWith("$CONTEXT_DIR_PREFIX$PATH_SEPARATOR") -> {
                    File(base, path.substring(CONTEXT_DIR_PREFIX.length + 1))
                }

                else -> {
                    null
                }
            }
        } else if (path.startsWith(CONTEXT_DIR_WITH_NAME_PREFIX)) {
            // Handle {contextDir:dirName} pattern
            val closeBraceIndex = path.indexOf(CLOSING_BRACE)
            if (closeBraceIndex > CONTEXT_DIR_WITH_NAME_PREFIX.length) {
                val dirName = path.substring(CONTEXT_DIR_WITH_NAME_PREFIX.length, closeBraceIndex)
                val base = prov.contextDir(dirName)
                val prefixLength = closeBraceIndex + 1 // +1 for the closing brace
                return when {
                    path.length == prefixLength -> {
                        base
                    }

                    path.length > prefixLength && path[prefixLength] == PATH_SEPARATOR[0] -> {
                        File(base, path.substring(prefixLength + 1))
                    }

                    else -> {
                        null
                    }
                }
            }
        }

        return null
    }
}

abstract class BaseKeyStoreLoader(
    private val type: String,
) : KeyStoreLoader {
    override suspend fun load(opts: KeyStoreLoaderOpts): KeyStore = loadSnapshot(opts).keyStore

    internal suspend fun loadSnapshot(opts: KeyStoreLoaderOpts): KeyStoreLoaderFactory.Snapshot {
        val ks = KeyStore.getInstance(type)

        val effectiveSource: KeyStoreLoaderOpts.Source =
            when (val src = opts.source) {
                is KeyStoreLoaderOpts.Source.File -> {
                    val (resolvedSrc, resolvedFile) = resolveFileSource(src)
                    withContext(Dispatchers.IO) {
                        ensureFileExistsAndInitialized(ks, resolvedFile, src.autoCreate, opts.keyStorePassword)
                    }
                    resolvedSrc
                }

                else -> {
                    src
                }
            }

        var loadedFileRevision: String? = null

        // Always load through the uniform channel path for all sources
        try {
            withContext(Dispatchers.IO) {
                KeyStoreUtils.openChannel(effectiveSource).toInputStream().use {
                    if (effectiveSource is KeyStoreLoaderOpts.Source.File) {
                        val bytes = it.readBytes()
                        ks.load(bytes.inputStream(), opts.keyStorePassword?.toCharArray())
                        loadedFileRevision = KeyStoreLoaderFactory.contentRevision(bytes)
                    } else {
                        ks.load(it, opts.keyStorePassword?.toCharArray())
                    }
                }
            }
        } catch (ioe: java.io.IOException) {
            if (effectiveSource is KeyStoreLoaderOpts.Source.File) {
                val mainFile = java.io.File(effectiveSource.path)
                val dir = mainFile.parentFile ?: java.io.File(".")
                val bakFile = java.io.File(dir, "${mainFile.name}.bak")
                if (bakFile.exists()) {
                    java.io.FileInputStream(bakFile).use { bakIn ->
                        val bytes = bakIn.readBytes()
                        ks.load(bytes.inputStream(), opts.keyStorePassword?.toCharArray())
                        loadedFileRevision = KeyStoreLoaderFactory.contentRevision(bytes)
                    }
                    try {
                        java.nio.file.Files.copy(
                            bakFile.toPath(),
                            mainFile.toPath(),
                            java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                        )
                    } catch (_: Throwable) {
                        // ignore restore failure; in-memory keystore is loaded
                    }
                } else {
                    throw ioe
                }
            } else {
                throw ioe
            }
        }
        return KeyStoreLoaderFactory.Snapshot(ks, loadedFileRevision)
    }

    private fun resolveFileSource(src: KeyStoreLoaderOpts.Source.File): Pair<KeyStoreLoaderOpts.Source.File, File> {
        val resolvedFile = PathPlaceholderInterpreter.resolve(src.path) ?: File(src.path)
        val resolvedSrc =
            if (resolvedFile.absolutePath != src.path) {
                src.copy(path = resolvedFile.absolutePath)
            } else {
                src
            }
        return resolvedSrc to resolvedFile
    }

    private suspend fun ensureFileExistsAndInitialized(
        ks: KeyStore,
        file: File,
        autoCreate: Boolean,
        password: String?,
    ) {
        withContext(Dispatchers.IO) {
            validateWritableFileLocation(file)
            if (!file.exists()) {
                if (!autoCreate) {
                    throw kotlinx.io.files.FileNotFoundException("Keystore file not found at ${file.absolutePath} and autoCreate=false")
                }
                // Ensure parent dirs
                file.parentFile?.let { parent ->
                    if (!parent.exists() && !parent.mkdirs()) {
                        throw java.io.IOException("Unable to create directories for path: ${parent.absolutePath}")
                    }
                }
                // Initialize empty keystore and persist it so subsequent channel-based load can read it
                ks.load(null, password?.toCharArray())
                FileOutputStream(file).use { out ->
                    ks.store(out, password?.toCharArray())
                }
            }
        }
    }

    private fun validateWritableFileLocation(file: File) {
        val parent = file.parentFile
        if (parent != null) {
            if (parent.exists() && !parent.isDirectory) {
                throw java.io.IOException("Parent path is not a directory: ${parent.absolutePath}")
            }
            if (!parent.exists() && !parent.mkdirs()) {
                throw java.io.IOException("Unable to create directories for path: ${parent.absolutePath}")
            }
            if (!parent.canWrite()) {
                throw java.io.IOException("Directory is not writable: ${parent.absolutePath}")
            }
        }
    }
}

/**
 * Loader implementation for JKS (Java Key Store) keystores.
 */
class JksLoader : BaseKeyStoreLoader(PredefinedKeyStoreTypes.JKS.keyStoreType)

/**
 * Loader implementation for PKCS#12 keystores.
 */
class Pkcs12Loader : BaseKeyStoreLoader(PredefinedKeyStoreTypes.PKCS12.keyStoreType)

/**
 * Loader implementation for BouncyCastle BKS keystores (Android ships the provider).
 */
class BksLoader : BaseKeyStoreLoader(PredefinedKeyStoreTypes.BKS.keyStoreType)
