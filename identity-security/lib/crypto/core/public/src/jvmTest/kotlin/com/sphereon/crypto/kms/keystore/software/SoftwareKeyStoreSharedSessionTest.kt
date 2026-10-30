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

import com.sphereon.crypto.core.KeyInfo
import com.sphereon.crypto.core.KeyVisibility
import com.sphereon.crypto.core.ResolvedKeyInfo
import com.sphereon.crypto.core.generic.KeyTypeMapping
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.crypto.core.interop.derPrivateKeyToJwk
import com.sphereon.crypto.core.interop.derPublicKeyToJwk
import com.sphereon.crypto.core.jose.Jwk
import com.sphereon.crypto.core.jose.JwkType
import com.sphereon.crypto.core.kms.KeyStoreLoaderOpts
import com.sphereon.crypto.core.kms.model.PredefinedKeyStoreTypes
import kotlinx.coroutines.test.runTest
import java.nio.file.Files
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import kotlin.test.Test
import java.security.KeyStore
import kotlin.test.assertFailsWith
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Locks in the cross-instance/cross-session sharing of one file-backed software keystore.
 *
 * Production defect: the platform `license` PKCS12 is read through a fixed, reused decrypt session
 * whose in-memory keystore was loaded early (with the self-generated recipient key, or empty). A
 * SEPARATE import session then durably stores the bundle recipient key on disk. The reused decrypt
 * session kept serving its stale in-memory copy, so it resolved the OLD entry for the alias and the
 * JWE unwrap failed.
 *
 * The keystore now reloads from disk when the file mtime advances past what an instance last loaded,
 * so a key stored through one instance is what any later read through a separately-constructed
 * instance over the same file resolves. Each test creates the READER instance BEFORE the WRITER
 * stores (the reused-session shape), then asserts the reader sees the durable write.
 */
class SoftwareKeyStoreSharedSessionTest {
    private fun configFor(path: String) =
        Pkcs12KeyStoreConfig(
            id = "license",
            password = "test-password",
            path = path,
            persist = true,
            overwriteAlias = true,
            keyVisibility = KeyVisibility.PRIVATE.keyVisibility,
        )

    /** A real EC P-256 private JWK, mirroring the bare license-recipient encryption key (no x5c). */
    private fun ecRecipientKey(alias: String): ResolvedKeyInfo<Jwk> {
        val generator = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
        val pair = generator.generateKeyPair()
        val priv = derPrivateKeyToJwk(pair.private.encoded)
        val pub = derPublicKeyToJwk(pair.public.encoded)
        val jwk = priv.copy(x = pub.x, y = pub.y, crv = priv.crv ?: pub.crv, kid = alias)
        return ResolvedKeyInfo(
            key = jwk,
            keyVisibility = KeyVisibility.PRIVATE,
            keyType = KeyTypeMapping.EC,
            alias = alias,
            providerId = "license",
            kid = alias,
            signatureAlgorithm = SignatureAlgorithm.ECDSA_SHA256,
        )
    }

    /**
     * The keystore file mtime resolution can be coarse (1s on some filesystems). The reload trigger
     * compares mtime, so make the writer's durable write land at a strictly newer mtime than the file
     * the reader first loaded.
     */
    private fun bumpFileMtime(path: String) {
        val file = java.io.File(path)
        if (file.exists()) {
            file.setLastModified(file.lastModified() + 2_000L)
        }
    }

    @Test
    fun keyStoreLoaderSharesRepeatedFileLoadsAndSupportsForcedReload() =
        runTest {
            val dir = Files.createTempDirectory("sks-loader-cache").toFile().also { it.deleteOnExit() }
            val path = dir.resolve("cached.p12").absolutePath
            val opts =
                KeyStoreLoaderOpts(
                    type = PredefinedKeyStoreTypes.PKCS12.keyStoreType,
                    source = KeyStoreLoaderOpts.Source.File(path, autoCreate = true),
                    keyStorePassword = "test-password",
                )

            KeyStoreLoaderFactory.clearCache()
            try {
                val first = KeyStoreLoaderFactory.load(opts)
                val second = KeyStoreLoaderFactory.load(opts)
                val reloaded = KeyStoreLoaderFactory.load(opts, forceReload = true)

                assertTrue(first === second, "repeated file loads should share the cached keystore")
                assertTrue(first !== reloaded, "forceReload must bypass the cached keystore")
            } finally {
                KeyStoreLoaderFactory.clearCache()
            }
        }

    @Test
    fun tenantInvalidationRemovesOnlyMatchingTenantKeyStoreLoads() =
        runTest {
            val dir = Files.createTempDirectory("sks-loader-tenant-cache").toFile().also { it.deleteOnExit() }
            val tenantAPath = dir.resolve("tenant-a/software.p12").apply { parentFile.mkdirs() }.absolutePath
            val tenantBPath = dir.resolve("tenant-b/software.p12").apply { parentFile.mkdirs() }.absolutePath
            val optsA =
                KeyStoreLoaderOpts(
                    type = PredefinedKeyStoreTypes.PKCS12.keyStoreType,
                    source = KeyStoreLoaderOpts.Source.File(tenantAPath, autoCreate = true),
                    keyStorePassword = "test-password",
                )
            val optsB =
                KeyStoreLoaderOpts(
                    type = PredefinedKeyStoreTypes.PKCS12.keyStoreType,
                    source = KeyStoreLoaderOpts.Source.File(tenantBPath, autoCreate = true),
                    keyStorePassword = "test-password",
                )

            KeyStoreLoaderFactory.clearCache()
            try {
                val firstA = KeyStoreLoaderFactory.load(optsA)
                val firstB = KeyStoreLoaderFactory.load(optsB)
                val result = KeyStoreLoaderFactory.invalidateTenant("tenant-a")
                val secondA = KeyStoreLoaderFactory.load(optsA)
                val secondB = KeyStoreLoaderFactory.load(optsB)

                assertEquals(2, result.keyStoresBefore)
                assertEquals(1, result.keyStoresAfter)
                assertEquals(1, result.keyStoresEvicted)
                assertTrue(firstA !== secondA, "invalidated tenant keystore should be loaded again")
                assertTrue(firstB === secondB, "other tenant keystore should remain cached")
            } finally {
                KeyStoreLoaderFactory.clearCache()
            }
        }

    @Test
    fun keyStoredThroughOneInstanceIsResolvedThroughAReusedSecondInstance() =
        runTest {
            KeyStoreLoaderFactory.clearCache()
            val dir = Files.createTempDirectory("sks-shared-session").toFile().also { it.deleteOnExit() }
            val path = dir.resolve("license.p12").absolutePath

            // The "decrypt session": built FIRST and reused. Touch it so it loads the file once.
            val reader = SoftwareKeyStoreService(configFor(path))
            // Force the lazy load + mtime baseline by listing (empty) keys.
            assertTrue(reader.listKeys().isEmpty(), "reader keystore should start empty")

            // The "import session": a separate instance that durably stores the recipient key.
            val writer = SoftwareKeyStoreService(configFor(path))
            val stored = writer.storeKey(ecRecipientKey("license-recipient"), "license", "license-recipient")
            writer.awaitPendingPersistenceCompletion()
            assertEquals("license-recipient", stored.alias)
            bumpFileMtime(path)

            // The reused reader must now resolve the durably-stored key (this is the bug that broke).
            // Request PRIVATE visibility, exactly as the KMS decrypt path does, so the private
            // recipient key material is exported.
            val resolved = reader.getKey(KeyInfo<Jwk>(kid = "license-recipient", keyVisibility = KeyVisibility.PRIVATE))
            assertEquals("license-recipient", resolved.alias)
            assertNotNull(
                (resolved.key as? JwkType)?.d,
                "reused decrypt-session instance must resolve the recipient key stored durably by the import session",
            )
        }

    @Test
    fun reusedInstanceResolvesTheOverwrittenKeyNotTheStaleSelfGeneratedOne() =
        runTest {
            KeyStoreLoaderFactory.clearCache()
            val dir = Files.createTempDirectory("sks-shared-overwrite").toFile().also { it.deleteOnExit() }
            val path = dir.resolve("license.p12").absolutePath

            // Seed the file with a STALE self-generated recipient key under the license alias, exactly
            // like the platform generating its own `license` recipient key before any bundle import.
            val seeder = SoftwareKeyStoreService(configFor(path))
            val staleKey = ecRecipientKey("license-recipient")
            seeder.storeKey(staleKey, "license", "license-recipient")
            seeder.awaitPendingPersistenceCompletion()
            val staleD = (staleKey.key as JwkType).d
            assertNotNull(staleD)

            // The reused decrypt session loads the file now (with the stale key cached in memory).
            val reader = SoftwareKeyStoreService(configFor(path))
            val before = reader.getKey(KeyInfo<Jwk>(kid = "license-recipient", keyVisibility = KeyVisibility.PRIVATE))
            assertEquals(staleD, (before.key as? JwkType)?.d, "reader should first see the stale self-generated key")

            // The import session OVERWRITES the same alias with the bundle's recipient key on disk.
            val importer = SoftwareKeyStoreService(configFor(path))
            val bundleKey = ecRecipientKey("license-recipient")
            importer.storeKey(bundleKey, "license", "license-recipient")
            importer.awaitPendingPersistenceCompletion()
            val bundleD = (bundleKey.key as JwkType).d
            assertNotNull(bundleD)
            assertTrue(staleD != bundleD, "fixture sanity: the two keys must differ")
            bumpFileMtime(path)

            // The reused reader must resolve the NEW (bundle) key, not the stale entry it had cached.
            val after = reader.getKey(KeyInfo<Jwk>(kid = "license-recipient", keyVisibility = KeyVisibility.PRIVATE))
            assertEquals(
                bundleD,
                (after.key as? JwkType)?.d,
                "reused instance must resolve the durably-overwritten bundle key, not the stale self-generated one",
            )
        }

    // Independent JCA file I/O deliberately bypasses this JVM's provider/factory caches,
    // reproducing the shared-file boundary of a second process without replacing a provider.
    private fun writeExternalAlias(path: String, sourceAlias: String, targetAlias: String) {
        val file = java.io.File(path)
        val modified = file.lastModified()
        val external = KeyStore.getInstance("PKCS12")
        file.inputStream().use { external.load(it, "test-password".toCharArray()) }
        val protection = KeyStore.PasswordProtection("test-password".toCharArray())
        external.setEntry(targetAlias, external.getEntry(sourceAlias, protection), protection)
        file.outputStream().use { external.store(it, "test-password".toCharArray()) }
        assertTrue(file.setLastModified(modified), "fixture preserves coarse file timestamps")
    }

    @Test
    fun freshServiceSeesExternalAliasWithWarmLoaderCache() = runTest {
        KeyStoreLoaderFactory.clearCache()
        val dir = Files.createTempDirectory("sks-external-new-service").toFile()
        try {
            val path = dir.resolve("shared.p12").absolutePath
            val writer = SoftwareKeyStoreService(configFor(path))
            writer.storeKey(ecRecipientKey("seed"), "license", "seed")
            writer.awaitPendingPersistenceCompletion()
            assertEquals(1, writer.listKeys().size)
            writeExternalAlias(path, "seed", "external-new")
            val reader = SoftwareKeyStoreService(configFor(path))
            assertEquals("external-new", reader.resolvePublicKeyByAlias("external-new").alias)
            assertEquals(2, reader.listKeys().size)
        } finally {
            KeyStoreLoaderFactory.clearCache()
            SoftwareKeyStoreStateCache.clear()
            dir.deleteRecursively()
        }
    }

    @Test
    fun reusedServiceSeesExternalAliasWithoutTimestampAdvance() = runTest {
        KeyStoreLoaderFactory.clearCache()
        val dir = Files.createTempDirectory("sks-external-reused-service").toFile()
        try {
            val path = dir.resolve("shared.p12").absolutePath
            val reader = SoftwareKeyStoreService(configFor(path))
            reader.storeKey(ecRecipientKey("seed"), "license", "seed")
            reader.awaitPendingPersistenceCompletion()
            assertEquals(1, reader.listKeys().size)
            writeExternalAlias(path, "seed", "external-new")
            assertEquals("external-new", reader.resolvePublicKeyByAlias("external-new").alias)
            assertEquals("external-new", reader.getKey(KeyInfo<Jwk>(kid = "external-new", keyVisibility = KeyVisibility.PRIVATE)).alias)
        } finally {
            KeyStoreLoaderFactory.clearCache()
            SoftwareKeyStoreStateCache.clear()
            dir.deleteRecursively()
        }
    }

    @Test
    fun externalOverwriteInvalidatesResolvedPrivateKeyCache() = runTest {
        KeyStoreLoaderFactory.clearCache()
        val dir = Files.createTempDirectory("sks-external-overwrite").toFile()
        try {
            val path = dir.resolve("shared.p12").absolutePath
            val reader = SoftwareKeyStoreService(configFor(path))
            val oldKey = ecRecipientKey("selected")
            val nextKey = ecRecipientKey("next")
            reader.storeKey(oldKey, "license", "selected")
            reader.storeKey(nextKey, "license", "next")
            reader.awaitPendingPersistenceCompletion()
            val request = KeyInfo<Jwk>(kid = "selected", keyVisibility = KeyVisibility.PRIVATE)
            assertEquals((oldKey.key as JwkType).d, (reader.getKey(request).key as JwkType).d)
            writeExternalAlias(path, "next", "selected")
            val fresh = SoftwareKeyStoreService(configFor(path))
            assertEquals((nextKey.key as JwkType).d, (fresh.getKey(request).key as JwkType).d)
            assertEquals((nextKey.key as JwkType).d, (reader.getKey(request).key as JwkType).d)
        } finally {
            KeyStoreLoaderFactory.clearCache()
            SoftwareKeyStoreStateCache.clear()
            dir.deleteRecursively()
        }
    }

    @Test
    fun corruptedExternalStoreCannotServeCachedKey() = runTest {
        KeyStoreLoaderFactory.clearCache()
        val dir = Files.createTempDirectory("sks-external-corrupt").toFile()
        try {
            val path = dir.resolve("shared.p12").absolutePath
            val reader = SoftwareKeyStoreService(configFor(path))
            reader.storeKey(ecRecipientKey("selected"), "license", "selected")
            reader.awaitPendingPersistenceCompletion()
            reader.resolvePublicKeyByAlias("selected")
            assertTrue(!java.io.File(path + ".bak").exists(), "corruption fixture has no recoverable backup")
            java.io.File(path).writeBytes(byteArrayOf(1, 2, 3))
            assertFailsWith<java.io.IOException> { reader.resolvePublicKeyByAlias("selected") }
        } finally {
            KeyStoreLoaderFactory.clearCache()
            SoftwareKeyStoreStateCache.clear()
            dir.deleteRecursively()
        }
    }

    @Test
    fun deletedExternalStoreCannotServeCachedKey() = runTest {
        KeyStoreLoaderFactory.clearCache()
        val dir = Files.createTempDirectory("sks-external-delete").toFile()
        try {
            val path = dir.resolve("shared.p12").absolutePath
            val reader = SoftwareKeyStoreService(configFor(path))
            reader.storeKey(ecRecipientKey("selected"), "license", "selected")
            reader.awaitPendingPersistenceCompletion()
            reader.resolvePublicKeyByAlias("selected")
            assertTrue(java.io.File(path).delete())
            assertFailsWith<java.io.IOException> { reader.resolvePublicKeyByAlias("selected") }
        } finally {
            KeyStoreLoaderFactory.clearCache()
            SoftwareKeyStoreStateCache.clear()
            dir.deleteRecursively()
        }
    }
}
