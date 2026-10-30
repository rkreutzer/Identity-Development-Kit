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
 */

package com.sphereon.identity.matching.impl.protection

import com.sphereon.core.api.Encoding
import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.decodeFrom
import com.sphereon.core.api.encodeToBase64Url
import com.sphereon.core.api.error.IdkError
import com.sphereon.crypto.core.CoseJoseKeyMappingService
import com.sphereon.crypto.core.KeyInfoType
import com.sphereon.crypto.core.KeyType
import com.sphereon.crypto.core.KeyVisibility
import com.sphereon.crypto.core.ManagedKeyInfo
import com.sphereon.crypto.core.ManagedKeyInfoType
import com.sphereon.crypto.core.ManagedKeyReference
import com.sphereon.crypto.core.ResolvedKeyInfo
import com.sphereon.crypto.core.ResolvedKeyInfoType
import com.sphereon.crypto.core.generic.CoseKeyPair
import com.sphereon.crypto.core.generic.JoseKeyPair
import com.sphereon.crypto.core.generic.KeyOperations
import com.sphereon.crypto.core.generic.KeyTypeMapping
import com.sphereon.crypto.core.generic.ManagedKeyPair
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.crypto.core.jose.JwaAlgorithm
import com.sphereon.crypto.core.jose.JwaKeyType
import com.sphereon.crypto.core.jose.Jwk
import com.sphereon.crypto.core.jose.JwkUse
import com.sphereon.crypto.core.kms.ContentEncryptionAlgorithm
import com.sphereon.crypto.core.kms.EncryptionResult
import com.sphereon.crypto.core.kms.GetAllCapabilitiesResult
import com.sphereon.crypto.core.kms.KeyAgreementAlgorithm
import com.sphereon.crypto.core.kms.KeyManagerService
import com.sphereon.crypto.core.kms.KeyResolverService
import com.sphereon.crypto.core.kms.KeyStoreService
import com.sphereon.crypto.core.kms.KeyWrapAlgorithm
import com.sphereon.crypto.core.kms.KmsProvider
import com.sphereon.crypto.core.kms.KmsProviderQuery
import com.sphereon.crypto.core.kms.QueryProviderResult
import com.sphereon.crypto.core.kms.QueryProvidersResult
import com.sphereon.crypto.core.kms.command.CreateRawSignatureResult
import com.sphereon.crypto.core.kms.command.DecryptArgs
import com.sphereon.crypto.core.kms.command.DecryptCommand
import com.sphereon.crypto.core.kms.command.DecryptResult
import com.sphereon.crypto.core.kms.command.DeleteKeyResult
import com.sphereon.crypto.core.kms.command.EncryptArgs
import com.sphereon.crypto.core.kms.command.EncryptCommand
import com.sphereon.crypto.core.kms.command.EncryptResult
import com.sphereon.crypto.core.kms.command.GenerateKeyArgs
import com.sphereon.crypto.core.kms.command.GenerateKeyCommand
import com.sphereon.crypto.core.kms.command.GenerateKeyResult
import com.sphereon.crypto.core.kms.command.GenerateMacArgs
import com.sphereon.crypto.core.kms.command.GenerateMacCommand
import com.sphereon.crypto.core.kms.command.GenerateMacResult
import com.sphereon.crypto.core.kms.command.GetKeyResult
import com.sphereon.crypto.core.kms.command.ListKeysArgs
import com.sphereon.crypto.core.kms.command.ListKeysCommand
import com.sphereon.crypto.core.kms.command.ListKeysResult
import com.sphereon.crypto.core.kms.command.PerformKeyAgreementResult
import com.sphereon.crypto.core.kms.command.ResolvePublicKeyResult
import com.sphereon.crypto.core.kms.command.SignDigestResult
import com.sphereon.crypto.core.kms.command.SignatureEncoding
import com.sphereon.crypto.core.kms.command.StoreKeyResult
import com.sphereon.crypto.core.kms.command.UnwrapKeyResult
import com.sphereon.crypto.core.kms.command.VerifyDigestResult
import com.sphereon.crypto.core.kms.command.VerifyRawSignatureResult
import com.sphereon.crypto.core.kms.command.WrapKeyResult
import com.sphereon.crypto.core.kms.model.IdentifierMethod
import com.sphereon.crypto.core.kms.model.KeyProviderSettings
import com.sphereon.crypto.core.toKeyReference
import com.sphereon.crypto.core.x509.Certificate
import com.sphereon.data.store.party.model.IdentifierProtectionMode
import com.sphereon.data.store.party.model.IdentifierType
import com.sphereon.identity.matching.protection.IdentifierProtectionErrors
import com.sphereon.identity.matching.protection.IdentifierProtectionKeyAccess
import com.sphereon.identity.matching.protection.IdentifierProtectionKeyProvisioner
import com.sphereon.identity.matching.protection.IdentifierProtectionPolicy
import com.sphereon.identity.matching.protection.NormalizationProfile
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.yield
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * End-to-end flow test for the REAL [KmsBackedIdentifierProtector] against a KMS whose key
 * lifecycle enforces the production contract: a key must be provisioned (generated/stored)
 * under its alias BEFORE it can be used for MAC or encrypt operations. Crypto is real
 * (javax.crypto HMAC-SHA256 and AES-256-GCM); only the command-bus plumbing is bridged.
 *
 * Identifier keys are created only by [IdentifierProtectionKeyProvisioner.provisionKeys]. Blind
 * indexing, protection and reveal refuse with [IdentifierProtectionErrors.KEY_NOT_PROVISIONED]
 * when the tenant has no key and never create one, and an existing key is used through the
 * provider it is recorded under.
 */
class KmsBackedIdentifierProtectorKmsFlowTest {
    private val tenant = "application"
    private val emailType = IdentifierType("email")
    private val emailPolicy =
        IdentifierProtectionPolicy(
            identifierType = emailType,
            mode = IdentifierProtectionMode.SEARCHABLE_BLIND_INDEX,
            normalization = NormalizationProfile.EMAIL,
        )

    private fun newProtector(
        kms: InMemoryAesGcmKms,
        providerId: String? = "software",
        macCommand: MapBackedGenerateMacCommand = MapBackedGenerateMacCommand(kms),
        listKeysCommand: ListKeysCommand = MapBackedListKeysCommand(kms),
        generateKeyCommand: GenerateKeyCommand = MapBackedGenerateKeyCommand(kms),
        keyAccess: IdentifierProtectionKeyAccess? = null,
    ): KmsBackedIdentifierProtector =
        KmsBackedIdentifierProtector(
            generateKeyCommand = generateKeyCommand,
            listKeysCommand = listKeysCommand,
            generateMacCommand = macCommand,
            encryptCommand = MapBackedEncryptCommand(kms),
            decryptCommand = MapBackedDecryptCommand(kms),
            providerId = providerId,
            keyAccess = keyAccess,
        )

    /** The protector's explicit key-creation seam; typed as [Any] so the lookup is a runtime check. */
    private fun provisionerOf(protector: Any): IdentifierProtectionKeyProvisioner = protector as IdentifierProtectionKeyProvisioner

    private suspend fun provision(
        kms: InMemoryAesGcmKms,
        providerId: String = "software",
        tenantId: String = tenant,
    ) {
        val result = provisionerOf(newProtector(kms, providerId = providerId)).provisionKeys(tenantId)
        assertTrue(result.isOk, "provisioning setup failed: ${result.errorOrNull()}")
    }

    private fun assertKeyNotProvisioned(error: IdkError?) {
        assertEquals(IdentifierProtectionErrors.KEY_NOT_PROVISIONED, error?.code, "expected a typed refusal, got $error")
    }

    @Test
    fun blindIndexOnFreshKmsRefusesWithTypedErrorAndCreatesNoKey() =
        runTest {
            val kms = InMemoryAesGcmKms()
            val protector = newProtector(kms)

            val result = protector.blindIndex(tenant, emailType, "Owner@Example.com", emailPolicy)

            assertTrue(result.isErr, "blind indexing must fail closed when the tenant key is missing")
            assertKeyNotProvisioned(result.errorOrNull())
            assertEquals(0, kms.generateCount, "a blind-index read must never create a key")
            assertTrue(kms.storedKeys.isEmpty(), "no key may appear as a side effect of a read: ${kms.storedKeys.keys}")
        }

    @Test
    fun protectOnFreshKmsRefusesWithTypedErrorAndCreatesNoKey() =
        runTest {
            val kms = InMemoryAesGcmKms()
            val protector = newProtector(kms)

            val result = protector.protect(tenant, "identity-1", emailType, "Owner@Example.com", emailPolicy)

            assertTrue(result.isErr, "protection must fail closed when the tenant keys are missing")
            assertKeyNotProvisioned(result.errorOrNull())
            assertEquals(0, kms.generateCount, "protection must never create identifier keys")
        }

    @Test
    fun revealWithoutEncryptionKeyRefusesWithTypedError() =
        runTest {
            val kms = InMemoryAesGcmKms()
            provision(kms)
            val protected =
                newProtector(kms).protect(tenant, "identity-1", emailType, "Owner@Example.com", emailPolicy)
                    .getOrNull() ?: error("protection setup failed")
            kms.storedKeys.remove("idfr:enc:$tenant")
            val generatedBefore = kms.generateCount

            val result = newProtector(kms).reveal(protected, tenant, "identity-1", emailType)

            assertTrue(result.isErr)
            assertKeyNotProvisioned(result.errorOrNull())
            assertEquals(generatedBefore, kms.generateCount, "reveal must never create a key")
        }

    @Test
    fun provisionKeysCreatesBothAliasesInTheConfiguredProviderAndIsIdempotent() =
        runTest {
            val kms = InMemoryAesGcmKms()
            val listKeys = MapBackedListKeysCommand(kms)
            val provisioner = provisionerOf(newProtector(kms, listKeysCommand = listKeys))

            assertTrue(provisioner.provisionKeys(tenant).isOk)
            assertEquals(setOf("idfr:bi:$tenant", "idfr:enc:$tenant"), kms.storedKeys.keys)
            assertEquals(setOf("software"), kms.storedKeys.values.map { it.providerId }.toSet())
            assertEquals(2, kms.generateCount)

            assertTrue(provisionerOf(newProtector(kms)).provisionKeys(tenant).isOk)
            assertEquals(2, kms.generateCount, "repeated provisioning must keep the existing keys")
        }

    @Test
    fun provisionKeysRefusesWithoutConfiguredProvider() =
        runTest {
            val kms = InMemoryAesGcmKms()

            val result = provisionerOf(newProtector(kms, providerId = null)).provisionKeys(tenant)

            assertTrue(result.isErr, "provider selection by algorithm alone must never create tenant keys")
            assertEquals(0, kms.generateCount)
        }

    @Test
    fun blindIndexUsesBoundKeyAccessWithoutCallingRequestSessionCommands() = runTest {
        val kms = InMemoryAesGcmKms()
        provision(kms)
        val original = newProtector(kms).protect(tenant, "identity-1", emailType, "Owner@Example.com", emailPolicy)
            .getOrNull() ?: error("initial protection failed")
        val lookups = mutableListOf<String>()
        val macs = mutableListOf<String>()
        val keyAccess = object : IdentifierProtectionKeyAccess {
            override suspend fun listKeys(tenantId: String, args: ListKeysArgs): IdkResult<ListKeysResult, IdkError> {
                assertEquals(tenant, tenantId)
                assertEquals("software", args.providerId)
                assertEquals("idfr:bi:$tenant", args.alias)
                lookups += tenantId
                return MapBackedListKeysCommand(kms).execute(args)
            }
            override suspend fun generateMac(tenantId: String, args: GenerateMacArgs): IdkResult<GenerateMacResult, IdkError> {
                assertEquals(tenant, tenantId)
                assertEquals("software", args.providerId)
                assertEquals("idfr:bi:$tenant", args.keyId)
                macs += tenantId
                return MapBackedGenerateMacCommand(kms).execute(args)
            }
        }
        val directLookup = object : ListKeysCommand by MapBackedListKeysCommand(kms) {
            override suspend fun execute(args: ListKeysArgs): IdkResult<ListKeysResult, IdkError> =
                error("request-session key lookup must not run")
        }
        val protector = newProtector(kms, listKeysCommand = directLookup, keyAccess = keyAccess)
        val result = protector.blindIndex(tenant, emailType, "owner@example.com", emailPolicy)
        assertTrue(result.isOk)
        assertEquals(original.valueHmac, result.value)
        assertEquals(listOf(tenant), lookups)
        assertEquals(listOf(tenant), macs)
    }

    @Test
    fun providerSelectionSeparatesApplicationAndCustomerTenants() {
        assertEquals(
            "software",
            identifierProtectionProviderId(
                sessionTenantId = "platform",
                applicationTenantId = "platform",
            ),
        )
        assertEquals(
            "default",
            identifierProtectionProviderId(
                sessionTenantId = "customer-tenant",
                applicationTenantId = "platform",
            ),
        )
    }

    @Test
    fun protectThenRevealRoundTripsThroughRealAesGcm() =
        runTest {
            val kms = InMemoryAesGcmKms()
            provision(kms)
            val protector = newProtector(kms)

            val protected =
                protector
                    .protect(tenant, "identity-1", emailType, "Owner@Example.com", emailPolicy)
                    .getOrNull() ?: error("protect failed")

            val revealed =
                protector
                    .reveal(protected, tenant, "identity-1", emailType)
                    .getOrNull() ?: error("reveal failed")

            assertEquals("owner@example.com", revealed, "reveal must return the normalized plaintext")
            assertEquals("idfr:enc:$tenant", protected.encKeyRef)
            assertEquals("idfr:bi:$tenant", protected.hmacKeyRef)
        }

    @Test
    fun repeatedProtectReusesProvisionedKeys() =
        runTest {
            val kms = InMemoryAesGcmKms()
            provision(kms)
            val listKeys = MapBackedListKeysCommand(kms)
            val protector = newProtector(kms, listKeysCommand = listKeys)

            protector.protect(tenant, "identity-1", emailType, "a@example.com", emailPolicy).getOrNull()
                ?: error("first protect failed")
            val keysAfterFirst = kms.storedKeys.keys.toSet()
            val firstListCount = listKeys.calls
            assertEquals(
                listOf<String?>("idfr:bi:$tenant", "idfr:enc:$tenant"),
                listKeys.requestedAliases.sortedBy { it },
                "Key discovery must request only the two selected tenant aliases",
            )

            protector.protect(tenant, "identity-2", emailType, "b@example.com", emailPolicy).getOrNull()
                ?: error("second protect failed")

            assertEquals(keysAfterFirst, kms.storedKeys.keys.toSet(), "Protection must not add keys")
            assertEquals(2, kms.generateCount, "Only provisioning generates keys")
            assertEquals(firstListCount, listKeys.calls, "Session-owned key references must avoid repeated KMS discovery")
        }

    @Test
    fun successfulGenerationWithoutMetadataReceiptFailsClosed() =
        runTest {
            val kms = InMemoryAesGcmKms()
            val generator = object : GenerateKeyCommand {
                override val isEnabled: Boolean = true
                override val inputTypeToken = typeToken<GenerateKeyArgs>()
                override val outputTypeToken = typeToken<GenerateKeyResult>()
                override suspend fun supports(args: Any): Boolean = args is GenerateKeyArgs
                override suspend fun execute(args: GenerateKeyArgs): IdkResult<GenerateKeyResult, IdkError> =
                    Ok(GenerateKeyResult())
            }
            val provisioner = provisionerOf(newProtector(kms, generateKeyCommand = generator))

            val result = provisioner.provisionKeys(tenant)

            assertTrue(result.isErr)
            assertTrue(result.error.message.defaultMessage.contains("metadata receipt"))
        }

    @Test
    fun generatedMetadataReceiptWithWrongAliasFailsClosed() =
        runTest {
            val kms = InMemoryAesGcmKms()
            val generator =
                FixedReceiptGenerateKeyCommand(
                    ManagedKeyReference(alias = "unrelated", providerId = "software"),
                )
            val provisioner = provisionerOf(newProtector(kms, generateKeyCommand = generator))

            val result = provisioner.provisionKeys(tenant)

            assertTrue(result.isErr)
            assertTrue(result.error.message.defaultMessage.contains("unexpected alias"))
        }

    @Test
    fun generatedMetadataReceiptWithWrongProviderFailsClosed() =
        runTest {
            val kms = InMemoryAesGcmKms()
            val generator =
                FixedReceiptGenerateKeyCommand(
                    ManagedKeyReference(alias = "idfr:bi:$tenant", providerId = "other-provider"),
                )
            val provisioner = provisionerOf(newProtector(kms, generateKeyCommand = generator))

            val result = provisioner.provisionKeys(tenant)

            assertTrue(result.isErr)
            assertTrue(result.error.message.defaultMessage.contains("unexpected provider"))
        }

    @Test
    fun exactAliasLookupReturningUnrelatedReferenceFailsClosedWithoutGeneration() =
        runTest {
            val kms = InMemoryAesGcmKms()
            val listKeys =
                FixedListKeysCommand(
                    arrayOf(ManagedKeyReference(alias = "unrelated", providerId = "software")),
                )
            val protector = newProtector(kms, listKeysCommand = listKeys)

            val result = protector.protect(tenant, "identity-1", emailType, "Owner@Example.com", emailPolicy)
            val provisioning = provisionerOf(protector).provisionKeys(tenant)

            assertTrue(result.isErr)
            assertTrue(result.error.message.defaultMessage.contains("unrelated reference"))
            assertTrue(provisioning.isErr, "an invalid lookup answer is an error, never a missing key")
            assertEquals(0, kms.generateCount, "An invalid exact-lookup response must never trigger key generation")
            assertEquals(
                setOf("idfr:bi:$tenant", "idfr:enc:$tenant"),
                listKeys.requestedAliases.toSet(),
                "both selected aliases must be validated",
            )
        }

    @Test
    fun concurrentProvisioningAcrossProtectorInstancesGeneratesEachKeyOnce() =
        runTest {
            val kms = InMemoryAesGcmKms()
            val listKeys = SnapshotYieldingListKeysCommand(kms)
            val provisioners =
                listOf(
                    provisionerOf(newProtector(kms, listKeysCommand = listKeys)),
                    provisionerOf(newProtector(kms, listKeysCommand = listKeys)),
                )

            provisioners
                .map { provisioner -> async { provisioner.provisionKeys(tenant) } }
                .awaitAll()
                .forEach { assertTrue(it.isOk, "concurrent provisioning failed: ${it.errorOrNull()}") }

            assertEquals(2, kms.generateCount, "Concurrent provisioning must create each tenant key exactly once")
        }

    @Test
    fun nullConfiguredProviderRoutesMacToResolvedKeyProvider() =
        runTest {
            val kms = InMemoryAesGcmKms()
            provision(kms)
            val macCommand = MapBackedGenerateMacCommand(kms)
            val protector = newProtector(kms, providerId = null, macCommand = macCommand)

            protector.protect(tenant, "identity-1", emailType, "Owner@Example.com", emailPolicy).getOrNull()
                ?: error("protect failed")

            assertEquals(
                "software",
                macCommand.lastProviderId,
                "MAC must use the provider returned by managed key resolution, not a null/default provider",
            )
        }

    @Test
    fun legacySingleProviderKeysRemainUsableAfterMultiProviderUpgrade() =
        runTest {
            // RC2 had a single software provider. Current deployments add more providers and may
            // therefore have a different registry default, while the persisted identifier keys
            // must remain in (and be used from) the original software keystore.
            val kms = InMemoryAesGcmKms(defaultProviderIdValue = "platform")
            provision(kms, providerId = "software")
            val legacyMacCommand = MapBackedGenerateMacCommand(kms)
            val legacyProtector = newProtector(kms, providerId = "software", macCommand = legacyMacCommand)
            val rc2Ciphertext =
                legacyProtector
                    .protect(tenant, "identity-rc2", emailType, "Rc2@Example.com", emailPolicy)
                    .getOrNull() ?: error("RC2 protection setup failed")
            val generatedAtRc2 = kms.generateCount

            val currentMacCommand = MapBackedGenerateMacCommand(kms)
            val currentProtector = newProtector(kms, providerId = null, macCommand = currentMacCommand)

            val revealed =
                currentProtector
                    .reveal(rc2Ciphertext, tenant, "identity-rc2", emailType)
                    .getOrNull() ?: error("current release must decrypt RC2 ciphertext")
            currentProtector
                .protect(tenant, "identity-current", emailType, "Current@Example.com", emailPolicy)
                .getOrNull() ?: error("current release must reuse RC2 identifier keys")

            assertEquals("rc2@example.com", revealed)
            assertEquals(generatedAtRc2, kms.generateCount, "Upgrade must not duplicate or rotate identifier keys")
            assertEquals("software", currentMacCommand.lastProviderId)
            assertEquals("software", kms.lastEncryptProviderId)
            assertEquals("software", kms.lastDecryptProviderId)
        }

    /**
     * Upgrade safety: a tenant whose keys already exist (created at onboarding by an earlier
     * release) keeps matching its stored blind indexes and decrypting its stored ciphertext, and
     * nothing is generated by any operation, including a repeated provisioning call.
     */
    @Test
    fun tenantWithExistingKeysKeepsWorkingWithoutAnyGeneration() =
        runTest {
            val kms = InMemoryAesGcmKms()
            // Keys as an earlier release left them: generated in the configured provider.
            kms.generateKey("software", "idfr:bi:$tenant", JwkUse.sig, null, SignatureAlgorithm.HMAC_SHA256, KeyVisibility.PRIVATE)
            kms.generateKey(
                "software",
                "idfr:enc:$tenant",
                JwkUse.enc,
                arrayOf(KeyOperations.ENCRYPT, KeyOperations.DECRYPT),
                null,
                KeyVisibility.PRIVATE,
            )
            val existingKeys = kms.storedKeys.keys.toSet()
            val generatedBefore = kms.generateCount
            val stored =
                newProtector(kms).protect(tenant, "identity-1", emailType, "Owner@Example.com", emailPolicy)
                    .getOrNull() ?: error("existing tenant protection failed")

            // A fresh process (new protector, empty cache) logs the same user in and reveals the value.
            val afterRestart = newProtector(kms)
            val loginIndex =
                afterRestart.blindIndex(tenant, emailType, " owner@EXAMPLE.com", emailPolicy)
                    .getOrNull() ?: error("existing tenant login lookup failed")
            val revealed =
                afterRestart.reveal(stored, tenant, "identity-1", emailType)
                    .getOrNull() ?: error("existing tenant reveal failed")
            assertTrue(provisionerOf(afterRestart).provisionKeys(tenant).isOk)

            assertEquals(stored.valueHmac, loginIndex, "the stored blind index must keep matching")
            assertEquals("owner@example.com", revealed)
            assertEquals(generatedBefore, kms.generateCount, "no operation may create a key for a provisioned tenant")
            assertEquals(existingKeys, kms.storedKeys.keys.toSet())
        }

    /**
     * A tenant whose configured provider no longer holds its identifier keys (the provider binding
     * moved to a keystore without the alias) still resolves the keys through the provider they are
     * recorded under. Nothing is created in the new provider, so existing blind indexes and
     * ciphertext keep working.
     */
    @Test
    fun changedTenantProviderStillResolvesTheRecordedKey() =
        runTest {
            val kms = InMemoryAesGcmKms()
            provision(kms, providerId = "software")
            val stored =
                newProtector(kms, providerId = "software")
                    .protect(tenant, "identity-1", emailType, "Owner@Example.com", emailPolicy)
                    .getOrNull() ?: error("initial protection failed")
            val generatedBefore = kms.generateCount

            val listKeys = MapBackedListKeysCommand(kms)
            val macCommand = MapBackedGenerateMacCommand(kms)
            // The configured provider is now "tenant-hsm", whose keystore does not hold the aliases.
            val moved = newProtector(kms, providerId = "tenant-hsm", macCommand = macCommand, listKeysCommand = listKeys)

            val loginIndex =
                moved.blindIndex(tenant, emailType, "owner@example.com", emailPolicy)
                    .getOrNull() ?: error("login lookup after a provider change must still succeed")
            val revealed =
                moved.reveal(stored, tenant, "identity-1", emailType)
                    .getOrNull() ?: error("reveal after a provider change must still succeed")
            val provisioning = provisionerOf(moved).provisionKeys(tenant)

            assertEquals(stored.valueHmac, loginIndex, "the stored blind index must keep matching")
            assertEquals("owner@example.com", revealed)
            assertTrue(provisioning.isOk, "provisioning must accept the key recorded under another provider")
            assertEquals(generatedBefore, kms.generateCount, "a provider change must never create a new identifier key")
            assertEquals("software", macCommand.lastProviderId, "the MAC must use the key's recorded provider")
            assertEquals("software", kms.lastDecryptProviderId, "decryption must use the key's recorded provider")
            assertTrue("tenant-hsm" in listKeys.requestedProviders, "the configured provider is asked first")
            assertTrue(null in listKeys.requestedProviders, "the key reference index is searched across providers")
        }
}

/**
 * In-memory [KeyManagerService] bridge with REAL crypto and the production key-lifecycle
 * contract: encrypt/decrypt/MAC fail unless the key alias was provisioned first via
 * generateKey/storeKey. Mirrors the software KMS provider's behavior where
 * `resolveKeyIfNeeded` fails for unknown aliases.
 */
private class InMemoryAesGcmKms(
    private val defaultProviderIdValue: String = "software",
) : KeyManagerService {
    val storedKeys = mutableMapOf<String, ResolvedKeyInfo<Jwk>>()
    var generateCount = 0
        private set
    var lastEncryptProviderId: String? = null
        private set
    var lastDecryptProviderId: String? = null
        private set

    private val random = SecureRandom()

    fun keyBytes(alias: String): ByteArray? = storedKeys[alias]?.key?.k?.decodeFrom(Encoding.BASE64URL)

    fun keyBytes(
        alias: String,
        providerId: String,
    ): ByteArray? =
        storedKeys[alias]
            ?.takeIf { it.providerId == providerId }
            ?.key
            ?.k
            ?.decodeFrom(Encoding.BASE64URL)

    // ===== Methods exercised by KmsBackedIdentifierProtector (real behavior) =====

    override suspend fun getKeyResult(keyInfo: KeyInfoType<*>): IdkResult<GetKeyResult, IdkError> =
        try {
            Ok(GetKeyResult(getKey(keyInfo)))
        } catch (expected: Exception) {
            Err(IdkError.NOT_FOUND_ERROR(resource = "Key", message = expected.message ?: "Key not found"))
        }

    override suspend fun generateKeyResult(
        providerId: String?,
        alias: String?,
        use: JwkUse?,
        keyOperations: Array<out KeyOperations>?,
        alg: SignatureAlgorithm?,
        keyVisibility: KeyVisibility?,
        walletUnitId: String?,
    ): IdkResult<GenerateKeyResult, IdkError> {
        val keyPair = generateKey(providerId, alias, use, keyOperations, alg, keyVisibility)
        val reference = keyPair.joseToManagedKeyInfo(keyVisibility ?: KeyVisibility.PRIVATE).toKeyReference()
        return Ok(GenerateKeyResult(keyPair = keyPair, keyReference = reference))
    }

    override suspend fun generateKey(
        providerId: String?,
        alias: String?,
        use: JwkUse?,
        keyOperations: Array<out KeyOperations>?,
        alg: SignatureAlgorithm?,
        keyVisibility: KeyVisibility?,
    ): ManagedKeyPair {
        requireNotNull(alias) { "This test KMS requires an alias for key generation" }
        require(
            (use == JwkUse.sig && alg == SignatureAlgorithm.HMAC_SHA256) ||
                (
                    use == JwkUse.enc &&
                        alg == null &&
                        keyOperations?.toSet() == setOf(KeyOperations.ENCRYPT, KeyOperations.DECRYPT)
                ),
        ) {
            "This test KMS requires HMAC-SHA256 for MAC keys or an algorithm-free AES key with purpose-specific operations; " +
                "requested use=$use alg=$alg keyOperations=${keyOperations?.toList()}"
        }
        generateCount++
        val rawKey = ByteArray(32).also { random.nextBytes(it) }
        val privateJwk =
            Jwk(
                kty = JwaKeyType.oct,
                k = rawKey.encodeToBase64Url(),
                alg =
                    if (use == JwkUse.sig && alg == SignatureAlgorithm.HMAC_SHA256) {
                        JwaAlgorithm.HS256
                    } else {
                        null
                    },
                use = (use ?: JwkUse.sig).value,
                kid = alias,
                generateKid = false,
            )
        storedKeys[alias] =
            ResolvedKeyInfo(
                key = privateJwk,
                keyVisibility = KeyVisibility.PRIVATE,
                keyType = KeyTypeMapping.Symmetric,
                alias = alias,
                providerId = providerId ?: defaultProviderIdValue,
                kid = alias,
                signatureAlgorithm = alg,
            )
        val publicJwk = privateJwk.copy(k = null)
        return ManagedKeyPair(
            kid = alias,
            providerId = providerId ?: defaultProviderIdValue,
            alias = alias,
            jose = JoseKeyPair(privateJwk, publicJwk),
            cose = CoseKeyPair(null, CoseJoseKeyMappingService.toCoseKey(publicJwk)),
        )
    }

    override suspend fun encryptResult(
        keyInfo: KeyInfoType<*>,
        plaintext: ByteArray,
        algorithm: ContentEncryptionAlgorithm,
        additionalAuthenticatedData: ByteArray?,
    ): IdkResult<EncryptResult, IdkError> {
        val alias =
            keyInfo.alias ?: keyInfo.kid
                ?: return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Encrypt requires an alias or kid"))
        val effectiveProviderId = keyInfo.providerId ?: defaultProviderIdValue
        lastEncryptProviderId = effectiveProviderId
        val resolved = storedKeys[alias]
        val keyBytes = if (resolved?.providerId == effectiveProviderId) keyBytes(alias) else null
        if (keyBytes == null) {
            return Err(
                IdkError.fromString(
                    message = "Encryption failed: Could not find key for alias $alias in provider $effectiveProviderId",
                ),
            )
        }
        require(algorithm == ContentEncryptionAlgorithm.A256GCM) { "This test KMS only supports A256GCM" }
        val iv = ByteArray(12).also { random.nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(keyBytes, "AES"), GCMParameterSpec(128, iv))
        additionalAuthenticatedData?.let { cipher.updateAAD(it) }
        val combined = cipher.doFinal(plaintext)
        return Ok(
            EncryptResult(
                ciphertext = combined.copyOfRange(0, combined.size - 16),
                iv = iv,
                authTag = combined.copyOfRange(combined.size - 16, combined.size),
            ),
        )
    }

    override suspend fun decryptResult(
        keyInfo: KeyInfoType<*>,
        ciphertext: ByteArray,
        algorithm: ContentEncryptionAlgorithm,
        iv: ByteArray,
        authTag: ByteArray,
        additionalAuthenticatedData: ByteArray?,
    ): IdkResult<DecryptResult, IdkError> {
        val alias =
            keyInfo.alias ?: keyInfo.kid
                ?: return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Decrypt requires an alias or kid"))
        val effectiveProviderId = keyInfo.providerId ?: defaultProviderIdValue
        lastDecryptProviderId = effectiveProviderId
        val resolved = storedKeys[alias]
        val keyBytes = if (resolved?.providerId == effectiveProviderId) keyBytes(alias) else null
        if (keyBytes == null) {
            return Err(
                IdkError.fromString(
                    message = "Decryption failed: Could not find key for alias $alias in provider $effectiveProviderId",
                ),
            )
        }
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(keyBytes, "AES"), GCMParameterSpec(128, iv))
            additionalAuthenticatedData?.let { cipher.updateAAD(it) }
            Ok(DecryptResult(cipher.doFinal(ciphertext + authTag)))
        } catch (expected: Exception) {
            Err(IdkError.fromString(message = "Decryption failed: ${expected::class.simpleName}: ${expected.message}"))
        }
    }

    // ===== Key store bookkeeping (real, map-backed) =====

    override val settings: KeyProviderSettings? = null

    override suspend fun listKeys(): Array<ManagedKeyReference> =
        storedKeys.entries
            .map { (alias, resolved) -> ManagedKeyInfo(alias = alias, providerId = resolved.providerId ?: "software", resolvedKeyInfo = resolved).toKeyReference() }
            .toTypedArray()

    override suspend fun getKey(keyInfo: KeyInfoType<*>): ManagedKeyInfoType<*> {
        val alias = keyInfo.alias ?: keyInfo.kid ?: throw IllegalArgumentException("Need alias or kid")
        val resolved =
            storedKeys[alias] ?: storedKeys.values.find { it.kid == alias }
                ?: throw IllegalArgumentException("Key not found: $alias")
        if (keyInfo.providerId != null && resolved.providerId != keyInfo.providerId) {
            throw IllegalArgumentException("Key not found: $alias in provider ${keyInfo.providerId}")
        }
        return ManagedKeyInfo(alias = resolved.alias ?: alias, providerId = resolved.providerId ?: "software", resolvedKeyInfo = resolved)
    }

    @Suppress("UNCHECKED_CAST")
    override suspend fun storeKey(
        keyInfo: ResolvedKeyInfoType<*>,
        providerId: String,
        alias: String,
        certChain: Array<Certificate>?,
    ): ManagedKeyInfoType<*> {
        storedKeys[alias] = ResolvedKeyInfo.fromDTO(keyInfo) as ResolvedKeyInfo<Jwk>
        return ManagedKeyInfo(alias = alias, providerId = providerId, resolvedKeyInfo = keyInfo)
    }

    override suspend fun deleteKey(keyInfo: KeyInfoType<*>): Boolean {
        val alias = keyInfo.alias ?: return false
        return storedKeys.remove(alias) != null
    }

    override suspend fun listKeysResult(providerId: String?): IdkResult<ListKeysResult, IdkError> = Ok(ListKeysResult(listKeys()))

    override suspend fun storeKeyResult(
        keyInfo: ResolvedKeyInfoType<*>,
        providerId: String,
        alias: String,
        certChain: Array<Certificate>?,
    ): IdkResult<StoreKeyResult, IdkError> = Ok(StoreKeyResult(storeKey(keyInfo, providerId, alias, certChain)))

    override suspend fun deleteKeyResult(keyInfo: KeyInfoType<*>): IdkResult<DeleteKeyResult, IdkError> = Ok(DeleteKeyResult(deleteKey(keyInfo)))

    override fun keyVisibility(): KeyVisibility = KeyVisibility.PRIVATE

    // ===== Not exercised by the protector =====

    override fun defaultProviderId(): String = defaultProviderIdValue

    override fun defaultResolverId(): String = unused()

    override fun registerProvider(
        provider: KmsProvider,
        makeDefaultKms: Boolean?,
    ): Unit = unused()

    override fun getProviderIds(): Array<String> = unused()

    override suspend fun getProviderById(id: String): KmsProvider = unused()

    override suspend fun getKmsBySignatureAlgorithm(signatureAlgorithm: SignatureAlgorithm): KmsProvider = unused()

    override fun getResolverById(id: String): KeyResolverService = unused()

    override fun getResolverByKeyTypeOrIdentifier(
        identifierMethod: IdentifierMethod?,
        keyType: KeyTypeMapping?,
        resolverId: String?,
    ): KeyResolverService = unused()

    override fun registerResolver(
        resolver: KeyResolverService,
        makeDefaultResolver: Boolean?,
    ): Unit = unused()

    @Deprecated("Use generateKey instead", ReplaceWith("generateKey(providerId, alias, use, keyOperations, alg, keyVisibility)"))
    override suspend fun generateKeyAsync(
        providerId: String?,
        alias: String?,
        use: JwkUse?,
        keyOperations: Array<out KeyOperations>?,
        alg: SignatureAlgorithm?,
        keyVisibility: KeyVisibility?,
    ): ManagedKeyPair = generateKey(providerId, alias, use, keyOperations, alg, keyVisibility)

    override fun getResolverIds(): Array<String> = unused()

    override suspend fun getProvider(
        providerId: String?,
        alg: SignatureAlgorithm?,
    ): KmsProvider = unused()

    override suspend fun createRawSignature(
        keyInfo: KeyInfoType<*>,
        input: ByteArray,
        requireX5Chain: Boolean,
    ): ByteArray = unused()

    override suspend fun isValidRawSignature(
        keyInfo: KeyInfoType<*>,
        input: ByteArray,
        signature: ByteArray,
    ): Boolean = unused()

    override suspend fun <KT : KeyType> resolvePublicKey(
        keyInfo: KeyInfoType<KT>,
        identifierMethod: IdentifierMethod?,
        trustedCerts: Array<String>?,
        verifyX509CertificateChain: Boolean?,
    ): ResolvedKeyInfoType<KT> = unused()

    override val keyStore: KeyStoreService
        get() = unused()

    override suspend fun signDigestResult(
        keyInfo: KeyInfoType<*>,
        digest: ByteArray,
        signatureAlgorithm: SignatureAlgorithm,
        signatureEncoding: SignatureEncoding,
        requireX5Chain: Boolean,
    ): IdkResult<SignDigestResult, IdkError> = unused()

    override suspend fun verifyDigestResult(
        keyInfo: KeyInfoType<*>,
        digest: ByteArray,
        signature: ByteArray,
        signatureAlgorithm: SignatureAlgorithm,
        signatureEncoding: SignatureEncoding,
    ): IdkResult<VerifyDigestResult, IdkError> = unused()

    override suspend fun signDigest(
        keyInfo: KeyInfoType<*>,
        digest: ByteArray,
        signatureAlgorithm: SignatureAlgorithm,
        signatureEncoding: SignatureEncoding,
        requireX5Chain: Boolean,
    ): ByteArray = unused()

    override suspend fun verifyDigest(
        keyInfo: KeyInfoType<*>,
        digest: ByteArray,
        signature: ByteArray,
        signatureAlgorithm: SignatureAlgorithm,
        signatureEncoding: SignatureEncoding,
    ): Boolean = unused()

    override suspend fun queryProvider(query: KmsProviderQuery): IdkResult<QueryProviderResult, IdkError> = unused()

    override suspend fun queryProviders(query: KmsProviderQuery): IdkResult<QueryProvidersResult, IdkError> = unused()

    override suspend fun getAllCapabilities(includeDisabled: Boolean): IdkResult<GetAllCapabilitiesResult, IdkError> = unused()

    override suspend fun encrypt(
        keyInfo: KeyInfoType<*>,
        plaintext: ByteArray,
        algorithm: ContentEncryptionAlgorithm,
        additionalAuthenticatedData: ByteArray?,
    ): EncryptionResult = unused()

    override suspend fun decrypt(
        keyInfo: KeyInfoType<*>,
        ciphertext: ByteArray,
        algorithm: ContentEncryptionAlgorithm,
        iv: ByteArray,
        authTag: ByteArray,
        additionalAuthenticatedData: ByteArray?,
    ): ByteArray = unused()

    override suspend fun wrapKey(
        wrappingKeyInfo: KeyInfoType<*>,
        keyToWrap: ByteArray,
        algorithm: KeyWrapAlgorithm,
    ): ByteArray = unused()

    override suspend fun unwrapKey(
        unwrappingKeyInfo: KeyInfoType<*>,
        wrappedKey: ByteArray,
        algorithm: KeyWrapAlgorithm,
    ): ByteArray = unused()

    override suspend fun performKeyAgreement(
        privateKeyInfo: KeyInfoType<*>,
        publicKeyInfo: KeyInfoType<*>,
        algorithm: KeyAgreementAlgorithm,
        keyDataLen: Int?,
    ): ByteArray = unused()

    override suspend fun createRawSignatureResult(
        keyInfo: KeyInfoType<*>,
        input: ByteArray,
        requireX5Chain: Boolean,
    ): IdkResult<CreateRawSignatureResult, IdkError> = unused()

    override suspend fun verifyRawSignatureResult(
        keyInfo: KeyInfoType<*>,
        input: ByteArray,
        signature: ByteArray,
    ): IdkResult<VerifyRawSignatureResult, IdkError> = unused()

    override suspend fun wrapKeyResult(
        wrappingKeyInfo: KeyInfoType<*>,
        keyToWrap: ByteArray,
        algorithm: KeyWrapAlgorithm,
    ): IdkResult<WrapKeyResult, IdkError> = unused()

    override suspend fun unwrapKeyResult(
        unwrappingKeyInfo: KeyInfoType<*>,
        wrappedKey: ByteArray,
        algorithm: KeyWrapAlgorithm,
    ): IdkResult<UnwrapKeyResult, IdkError> = unused()

    override suspend fun performKeyAgreementResult(
        privateKeyInfo: KeyInfoType<*>,
        publicKeyInfo: KeyInfoType<*>,
        algorithm: KeyAgreementAlgorithm,
        keyDataLen: Int?,
    ): IdkResult<PerformKeyAgreementResult, IdkError> = unused()

    override suspend fun resolvePublicKeyResult(
        keyInfo: KeyInfoType<*>,
        identifierMethod: IdentifierMethod?,
        trustedCerts: Array<String>?,
        verifyX509CertificateChain: Boolean?,
    ): IdkResult<ResolvePublicKeyResult, IdkError> = unused()

    private fun unused(): Nothing = throw UnsupportedOperationException("Not exercised by KmsBackedIdentifierProtector")
}

/**
 * [GenerateMacCommand] bridge computing a REAL HMAC-SHA256 with the key bytes provisioned in
 * the shared [InMemoryAesGcmKms]. Enforces the production contract: the key alias must exist.
 */
private class MapBackedGenerateMacCommand(
    private val kms: InMemoryAesGcmKms,
) : GenerateMacCommand {
    var lastProviderId: String? = null
        private set

    override val isEnabled: Boolean = true
    override val inputTypeToken = typeToken<GenerateMacArgs>()
    override val outputTypeToken = typeToken<GenerateMacResult>()

    override suspend fun supports(args: Any): Boolean = args is GenerateMacArgs

    override suspend fun execute(args: GenerateMacArgs): IdkResult<GenerateMacResult, IdkError> {
        lastProviderId = args.providerId
        val effectiveProviderId = args.providerId ?: kms.defaultProviderId()
        val keyBytes =
            kms.keyBytes(args.keyId, effectiveProviderId)
                ?: return Err(IdkError.NOT_FOUND_ERROR(resource = "Key", message = "MAC key '${args.keyId}' not found"))
        val mac =
            Mac
                .getInstance("HmacSHA256")
                .apply { init(SecretKeySpec(keyBytes, "HmacSHA256")) }
                .doFinal(args.message)
        return Ok(
            GenerateMacResult(
                mac = mac,
                macMultibase = "f" + mac.joinToString("") { byte -> "%02x".format(byte) },
                digestAlgorithm = args.digestAlgorithm,
            ),
        )
    }
}

private class MapBackedGenerateKeyCommand(
    private val kms: InMemoryAesGcmKms,
) : GenerateKeyCommand {
    override val isEnabled: Boolean = true
    override val inputTypeToken = typeToken<GenerateKeyArgs>()
    override val outputTypeToken = typeToken<GenerateKeyResult>()

    override suspend fun supports(args: Any): Boolean = args is GenerateKeyArgs

    override suspend fun execute(args: GenerateKeyArgs): IdkResult<GenerateKeyResult, IdkError> =
        kms.generateKeyResult(
            providerId = args.providerId,
            alias = args.alias,
            use = args.use,
            keyOperations = args.keyOperations,
            alg = args.alg,
            keyVisibility = args.keyVisibility,
        )
}

private class FixedReceiptGenerateKeyCommand(
    private val reference: ManagedKeyReference,
) : GenerateKeyCommand {
    override val isEnabled: Boolean = true
    override val inputTypeToken = typeToken<GenerateKeyArgs>()
    override val outputTypeToken = typeToken<GenerateKeyResult>()

    override suspend fun supports(args: Any): Boolean = args is GenerateKeyArgs

    override suspend fun execute(args: GenerateKeyArgs): IdkResult<GenerateKeyResult, IdkError> =
        Ok(GenerateKeyResult(keyReference = reference))
}

private class MapBackedListKeysCommand(
    private val kms: InMemoryAesGcmKms,
) : ListKeysCommand {
    var calls: Int = 0
        private set
    val requestedAliases = mutableListOf<String?>()
    val requestedProviders = mutableListOf<String?>()
    override val isEnabled: Boolean = true
    override val inputTypeToken = typeToken<ListKeysArgs>()
    override val outputTypeToken = typeToken<ListKeysResult>()

    override suspend fun supports(args: Any): Boolean = args is ListKeysArgs

    override suspend fun execute(args: ListKeysArgs): IdkResult<ListKeysResult, IdkError> {
        calls += 1
        requestedAliases += args.alias
        requestedProviders += args.providerId
        return kms.listKeysResult(args.providerId).map { result -> result.matching(args) }
    }
}

private class FixedListKeysCommand(
    private val references: Array<ManagedKeyReference>,
) : ListKeysCommand {
    val requestedAliases = mutableListOf<String?>()
    override val isEnabled: Boolean = true
    override val inputTypeToken = typeToken<ListKeysArgs>()
    override val outputTypeToken = typeToken<ListKeysResult>()

    override suspend fun supports(args: Any): Boolean = args is ListKeysArgs

    override suspend fun execute(args: ListKeysArgs): IdkResult<ListKeysResult, IdkError> {
        requestedAliases += args.alias
        return Ok(ListKeysResult(references))
    }
}

/** Yields after each exact-alias snapshot so the process-wide provisioning lock is exercised. */
private class SnapshotYieldingListKeysCommand(
    private val kms: InMemoryAesGcmKms,
) : ListKeysCommand {
    override val isEnabled: Boolean = true
    override val inputTypeToken = typeToken<ListKeysArgs>()
    override val outputTypeToken = typeToken<ListKeysResult>()

    override suspend fun supports(args: Any): Boolean = args is ListKeysArgs

    override suspend fun execute(args: ListKeysArgs): IdkResult<ListKeysResult, IdkError> {
        val snapshot = kms.listKeysResult(args.providerId).map { result -> result.matching(args) }
        yield()
        return snapshot
    }
}

private class MapBackedEncryptCommand(
    private val kms: InMemoryAesGcmKms,
) : EncryptCommand {
    override val isEnabled: Boolean = true
    override val inputTypeToken = typeToken<EncryptArgs>()
    override val outputTypeToken = typeToken<EncryptResult>()

    override suspend fun supports(args: Any): Boolean = args is EncryptArgs

    override suspend fun execute(args: EncryptArgs): IdkResult<EncryptResult, IdkError> =
        kms.encryptResult(
            keyInfo = requireNotNull(args.keyInfo),
            plaintext = args.plaintext,
            algorithm = args.algorithm,
            additionalAuthenticatedData = args.additionalAuthenticatedData,
        )
}

private class MapBackedDecryptCommand(
    private val kms: InMemoryAesGcmKms,
) : DecryptCommand {
    override val isEnabled: Boolean = true
    override val inputTypeToken = typeToken<DecryptArgs>()
    override val outputTypeToken = typeToken<DecryptResult>()

    override suspend fun supports(args: Any): Boolean = args is DecryptArgs

    override suspend fun execute(args: DecryptArgs): IdkResult<DecryptResult, IdkError> =
        kms.decryptResult(
            keyInfo = requireNotNull(args.keyInfo),
            ciphertext = args.ciphertext,
            algorithm = args.algorithm,
            iv = args.iv,
            authTag = args.authTag,
            additionalAuthenticatedData = args.additionalAuthenticatedData,
        )
}

/**
 * Mirrors the managed key store: an exact provider id selects only that provider's keys, while a
 * null provider id searches the key reference index across every provider.
 */
private fun ListKeysResult.matching(args: ListKeysArgs): ListKeysResult =
    ListKeysResult(
        keys
            .filter { args.alias == null || it.alias == args.alias }
            .filter { args.providerId == null || it.providerId == args.providerId }
            .toTypedArray(),
    )
