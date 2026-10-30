/*
 * Copyright 2026 Sphereon International B.V.
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

package com.sphereon.wallet.wsca.impl

import app.cash.sqldelight.driver.jdbc.asJdbcDriver
import com.sphereon.crypto.key.persistence.KeyReferenceStore
import com.sphereon.crypto.key.persistence.KeyReferenceHistoryCapability
import com.sphereon.crypto.key.persistence.sqlite.KeyReferenceDatabaseSqlite
import com.sphereon.crypto.key.persistence.sqlite.SqliteKeyReferenceStoreImpl
import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import java.nio.file.Files

import com.sphereon.core.api.Err
import com.sphereon.core.api.Ok
import com.sphereon.core.api.decodeFromBase64Url
import com.sphereon.core.api.encodeToBase64Url
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.session.asCoreApiServiceGraph
import com.sphereon.core.compat.Uuid
import com.sphereon.core.defaults.random.defaultSecureRandom
import com.sphereon.crypto.core.KeyInfo
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.crypto.core.jose.Jwk
import com.sphereon.crypto.core.jose.JwaCurve
import com.sphereon.crypto.core.jose.JwaKeyType
import com.sphereon.crypto.core.kms.KeyManagerService
import com.sphereon.crypto.core.kms.asKeyManagerServiceGraph
import com.sphereon.crypto.kms.provider.software.SoftwareKmsProviderConfig
import com.sphereon.crypto.kms.provider.software.SoftwareKmsProviderFactoryImpl
import com.sphereon.oauth2.common.command.DpopProofAssembly
import com.sphereon.wallet.wscd.testfixtures.createWalletAppGraph
import com.sphereon.wallet.unit.SecureComponentUsage
import com.sphereon.wallet.unit.WalletAttestedKeyRef
import com.sphereon.wallet.unit.WalletKeystoreRef
import com.sphereon.wallet.unit.WalletKeystoreSecurityLevel
import com.sphereon.wallet.unit.WalletPrivateKeyProtectionEvidence
import com.sphereon.wallet.unit.WalletProviderAttestationSignerRef
import com.sphereon.wallet.unit.WalletSecureComponentType
import com.sphereon.wallet.unit.WalletUserAuthenticationEvidence
import com.sphereon.wallet.unit.attestation.KeyAttestationIssueRequest
import com.sphereon.wallet.unit.attestation.LocalWalletProviderAttestationSignerResolver
import com.sphereon.wallet.unit.attestation.WalletAttestationSigner
import com.sphereon.wallet.unit.attestation.WalletAttestationSignerProfile
import com.sphereon.wallet.unit.attestation.WalletAttestationSigningRequest
import com.sphereon.wallet.unit.attestation.WalletAttestationSigningResult
import com.sphereon.wallet.unit.attestation.WalletProviderAttestationSignerResolver
import com.sphereon.wallet.unit.attestation.WalletUnitAttestationProfile
import com.sphereon.wallet.wsca.WscaClientAttestationAuthRequest
import com.sphereon.wallet.wsca.WscaDpopProofRequest
import com.sphereon.wallet.wsca.Wsca
import com.sphereon.wallet.wsca.WscaSigningRequest
import com.sphereon.wallet.wsca.WscaPreparedSigningFactory
import com.sphereon.wallet.wsca.WscaUserAuthenticationStatus
import com.sphereon.wallet.wscd.ActivationProof
import com.sphereon.wallet.wscd.ActivationProofKind
import com.sphereon.wallet.wscd.Wscd
import com.sphereon.wallet.wscd.WscdKeyHandle
import com.sphereon.wallet.wscd.WscdKeySpec
import com.sphereon.wallet.wscd.WscdProfile
import com.sphereon.wallet.wscd.software.KmsProviderBootstrap
import com.sphereon.wallet.wscd.software.SoftwareWscd
import dev.whyoleg.cryptography.CryptographyProvider
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertContentEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Clock
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.seconds

/**
 * Real-crypto (software-KMS backed) unit tests for [LocalWsca] wired over a real [SoftwareWscd].
 * No stubs: keys are generated in and signatures produced by the software KMS that sits behind
 * the WSCA/WSCD boundary - [LocalWsca] itself never touches it directly, only through [SoftwareWscd].
 *
 * DPoP proof assembly and signing is always available via
 * [com.sphereon.oauth2.common.command.DpopProofAssembly] + [SoftwareWscd], so there is no failure
 * mode for a missing `CreateDpopProofCommand`; the seam-equivalent failure case is
 * [createDpopProofFailsWhenKeyWasNeverProvisioned] (the WSCD rejects signing for a key it never
 * provisioned).
 *
 * Placed in jvmTest to reuse the module's real-KMS graph builder [createWalletAppGraph] (JVM-only,
 * matching the pattern used in lib-wallet-wscd-software's own jvmTest). The holder-proof path is
 * additionally exercised across the jvm+jsNode+wasmJsNode matrix by the wallet-runner E2E tests,
 * which drive issuance through this same surface.
 */
class LocalWscaTest {
    @Test
    fun ensureKeyIsIdempotentPerWalletUnitAndReturnsUsablePublicKey() =
        runTest {
            val wsca = newLocalWsca().wsca

            val first = wsca.ensureKey("wallet-a", SecureComponentUsage.WALLET_CREDENTIAL_PROOF, SignatureAlgorithm.ECDSA_SHA256)
            val second = wsca.ensureKey("wallet-a", SecureComponentUsage.WALLET_CREDENTIAL_PROOF, SignatureAlgorithm.ECDSA_SHA256)

            assertTrue(first.isOk, "ensureKey failed: ${if (first.isErr) first.error else ""}")
            assertTrue(second.isOk)
            // Idempotent: same wallet instance -> same key (same public key + reference).
            assertEquals(first.value.keyRef, second.value.keyRef)
            assertEquals(first.value.publicKeyJwk, second.value.publicKeyJwk)
            assertNotNull(first.value.publicKeyJwk, "ref must carry a public JWK")
            assertEquals("ES256", first.value.algorithm)

            // A different wallet instance gets a distinct key.
            val other = wsca.ensureKey("wallet-b", SecureComponentUsage.WALLET_CREDENTIAL_PROOF, SignatureAlgorithm.ECDSA_SHA256)
            assertTrue(other.isOk)
            assertTrue(other.value.keyRef != first.value.keyRef)
        }

    @Test
    fun signProducesSignatureVerifiableAgainstTheUnitHeldPublicKey() =
        runTest {
            val setup = newLocalWsca()

            val ref =
                setup.wsca
                    .ensureKey("wallet-sign", SecureComponentUsage.WALLET_CREDENTIAL_PROOF, SignatureAlgorithm.ECDSA_SHA256)
                    .let {
                        assertTrue(it.isOk, "ensureKey failed")
                        it.value
                    }

            val signingInput = "wallet-unit-signing-input".encodeToByteArray()
            val signature = prepareAndSign(setup.wsca, "wallet-sign", ref, signingInput, "test:sign")
            assertTrue(signature.isOk, "sign failed: ${if (signature.isErr) signature.error else ""}")

            // Verify through the existing KMS signature-verification path, resolving the key by its
            // unit-provisioned reference.
            val verify =
                setup.kms.verifyRawSignatureResult(
                    keyInfo = KeyInfo<Nothing>(alias = ref.keyRef, providerId = ref.keystore?.providerId),
                    input = signingInput,
                    signature = signature.value,
                )
            assertTrue(verify.isOk, "verify failed: ${if (verify.isErr) verify.error else ""}")
            assertTrue(verify.value.isValid, "signature over the signing input must verify against the unit key")
        }

    // ---------------------------------------------------------------------------------------
    // sign()/createDpopProof() route through Wsca.userAuthentication instead of
    // the removed silent localUserAuthPlaceholder: a denied ceremony must block signing, and a
    // granted one must be observable on LocalWsca.userAuthentication.state.
    // ---------------------------------------------------------------------------------------

    @Test
    fun signMovesUserAuthenticationToAuthenticatedOnSuccess() =
        runTest {
            val setup = newLocalWsca()
            assertEquals(WscaUserAuthenticationStatus.IDLE, setup.wsca.userAuthentication.state.value.status)

            val ref =
                setup.wsca
                    .ensureKey("wallet-auth-state", SecureComponentUsage.WALLET_CREDENTIAL_PROOF, SignatureAlgorithm.ECDSA_SHA256)
                    .let {
                        assertTrue(it.isOk, "ensureKey failed")
                        it.value
                    }

            val signature = prepareAndSign(setup.wsca, "wallet-auth-state", ref, "signing-input".encodeToByteArray(), "test:auth-state")

            assertTrue(signature.isOk, "sign failed: ${if (signature.isErr) signature.error else ""}")
            assertEquals(WscaUserAuthenticationStatus.AUTHENTICATED, setup.wsca.userAuthentication.state.value.status)
            assertEquals(ActivationProofKind.LOCAL_USER_AUTH, setup.wsca.userAuthentication.state.value.lastActivationKind)
        }

    @Test
    fun signFailsClosedWhenTheUserAuthenticationCeremonyIsDenied() =
        runTest {
            val denied = IdkError.fromString(code = "test.wallet_user_authenticator.denied", message = "user declined")
            val setup = newLocalWsca(userAuthenticator = WalletUserAuthenticator { Err(denied) })
            val ref =
                setup.wsca
                    .ensureKey("wallet-auth-denied", SecureComponentUsage.WALLET_CREDENTIAL_PROOF, SignatureAlgorithm.ECDSA_SHA256)
                    .let {
                        assertTrue(it.isOk, "ensureKey failed")
                        it.value
                    }

            val signature = prepareAndSign(setup.wsca, "wallet-auth-denied", ref, "signing-input".encodeToByteArray(), "test:auth-denied")

            assertTrue(signature.isErr, "sign must fail closed when the user-authentication ceremony is denied")
            assertEquals("test.wallet_user_authenticator.denied", signature.error.code)
            assertEquals(WscaUserAuthenticationStatus.FAILED, setup.wsca.userAuthentication.state.value.status)
        }

    @Test
    fun preparedSignRejectsEveryRequestAndContextMutationBeforeAuthentication() =
        runTest {
            var authenticationCalls = 0
            val setup =
                newLocalWsca(
                    userAuthenticator = WalletUserAuthenticator {
                        authenticationCalls++
                        Err(IdkError.fromString(code = "test.unexpected_authentication", message = "must not authenticate"))
                    },
                )
            val keyRef = WalletAttestedKeyRef("prepared-key", "ES256", walletUnitId = "wallet-prepared")
            val request =
                WscaSigningRequest(
                    walletUnitId = "wallet-prepared",
                    keyRef = keyRef,
                    walletAccountId = "account-prepared",
                    signingInput = "exact prepared bytes".encodeToByteArray(),
                    operationBinding = "prepared-operation",
                    audience = "prepared-audience",
                    nonce = "prepared-nonce",
                )
            val prepared = setup.wsca.prepareSign(request).getOrElse { error("prepare failed: $it") }

            val mutations =
                listOf(
                    "wallet unit" to request.copy(walletUnitId = "other-wallet"),
                    "key ref" to request.copy(keyRef = keyRef.copy(keyRef = "other-key")),
                    "wallet account" to request.copy(walletAccountId = "other-account"),
                    "operation binding" to request.copy(operationBinding = "other-operation"),
                    "audience" to request.copy(audience = "other-audience"),
                    "nonce" to request.copy(nonce = "other-nonce"),
                    "signing bytes" to request.copy(signingInput = "changed bytes".encodeToByteArray()),
                )
            mutations.forEach { (label, mutated) ->
                val result = setup.wsca.sign(prepared, mutated)
                assertTrue(result.isErr, "$label mutation must be rejected")
                assertEquals("ILLEGAL_ARGUMENT_ERROR", result.error.code, "$label mutation error")
            }

            val foreignFactory = WscaPreparedSigningFactory.create()
            val forgedContexts =
                listOf(
                    "digest" to prepared.digestBinding.replace("sha256:", "sha512:"),
                    "operation type" to "wallet.wsca.forged.sign",
                )
            forgedContexts.forEach { (label, value) ->
                val forged =
                    foreignFactory.mint(
                        walletUnitId = prepared.walletUnitId,
                        keyRef = prepared.keyRef,
                        walletAccountId = prepared.walletAccountId,
                        operationBinding = prepared.operationBinding,
                        operationType = if (label == "operation type") value else prepared.operationType,
                        digestBinding = if (label == "digest") value else prepared.digestBinding,
                        nonce = prepared.nonce,
                        audience = prepared.audience,
                        signingInput = prepared.signingInput,
                    )
                val result = setup.wsca.sign(forged, request)
                assertTrue(result.isErr, "$label mutation must be rejected")
                assertEquals("ILLEGAL_ARGUMENT_ERROR", result.error.code, "$label mutation error")
            }
            val foreignInstance = newLocalWsca(userAuthenticator = WalletUserAuthenticator {
                authenticationCalls++
                Err(IdkError.fromString(code = "test.unexpected_foreign_authentication", message = "must not authenticate"))
            }).wsca
            val foreignInstanceResult = foreignInstance.sign(prepared, request)
            assertTrue(foreignInstanceResult.isErr, "a prepared context from another WSCA instance must be rejected")
            assertEquals("ILLEGAL_ARGUMENT_ERROR", foreignInstanceResult.error.code)
            assertEquals(0, authenticationCalls, "all prepared-context failures must precede authentication")
        }

    @Test
    fun createDpopProofFailsClosedWhenTheUserAuthenticationCeremonyIsDenied() =
        runTest {
            val denied = IdkError.fromString(code = "test.wallet_user_authenticator.denied", message = "user declined")
            val setup = newLocalWsca(userAuthenticator = WalletUserAuthenticator { Err(denied) })
            val key =
                setup.wsca
                    .ensureKey("wallet-dpop-auth-denied", SecureComponentUsage.WALLET_ATTESTATION, SignatureAlgorithm.ECDSA_SHA256)
                    .let {
                        assertTrue(it.isOk, "ensureKey failed")
                        it.value
                    }

            val result =
                setup.wsca.createDpopProof(
                    WscaDpopProofRequest(
                        walletUnitId = "wallet-dpop-auth-denied",
                        operationBinding = "test:dpop:auth-denied",
                        keyRef = key,
                        httpMethod = "POST",
                        httpUrl = "https://issuer.example/token",
                    ),
                )

            assertTrue(result.isErr, "createDpopProof must fail closed when the user-authentication ceremony is denied")
            assertEquals("test.wallet_user_authenticator.denied", result.error.code)
        }

    @Test
    fun createCredentialKeyMintsADistinctKeyOnEveryCall() =
        runTest {
            val wsca = newLocalWsca().wsca

            val first =
                wsca.createCredentialKey("wallet-credential", SecureComponentUsage.WALLET_CREDENTIAL_PROOF, SignatureAlgorithm.ECDSA_SHA256)
            val second =
                wsca.createCredentialKey("wallet-credential", SecureComponentUsage.WALLET_CREDENTIAL_PROOF, SignatureAlgorithm.ECDSA_SHA256)

            assertTrue(first.isOk, "createCredentialKey failed: ${if (first.isErr) first.error else ""}")
            assertTrue(second.isOk, "createCredentialKey failed: ${if (second.isErr) second.error else ""}")
            // Non-idempotent: every call mints a brand-new key, even for the same wallet instance.
            assertTrue(first.value.keyRef != second.value.keyRef, "each call must mint a distinct key reference")
            assertTrue(first.value.publicKeyJwk != second.value.publicKeyJwk, "each call must mint a distinct public key")
            assertEquals("ES256", first.value.algorithm)
        }

    @Test
    fun createCredentialKeyRegistersTheKeyForSigning() =
        runTest {
            val setup = newLocalWsca()

            val ref =
                setup.wsca
                    .createCredentialKey("wallet-credential-sign", SecureComponentUsage.WALLET_CREDENTIAL_PROOF, SignatureAlgorithm.ECDSA_SHA256)
                    .let {
                        assertTrue(it.isOk, "createCredentialKey failed")
                        it.value
                    }

            val signingInput = "wallet-unit-credential-signing-input".encodeToByteArray()
            val signature = prepareAndSign(setup.wsca, "wallet-credential-sign", ref, signingInput, "test:credential-sign")
            assertTrue(signature.isOk, "sign failed: ${if (signature.isErr) signature.error else ""}")

            val verify =
                setup.kms.verifyRawSignatureResult(
                    keyInfo = KeyInfo<Nothing>(alias = ref.keyRef, providerId = ref.keystore?.providerId),
                    input = signingInput,
                    signature = signature.value,
                )
            assertTrue(verify.isOk, "verify failed: ${if (verify.isErr) verify.error else ""}")
            assertTrue(verify.value.isValid, "signature over the signing input must verify against the freshly minted credential key")
        }

    @Test
    fun discardCredentialKeyPermanentlyRemovesAnUnboundFreshKey() =
        runTest {
            val databaseFile = Files.createTempFile("wallet-discard-history-", ".sqlite")
            val jdbcUrl = "jdbc:sqlite:${databaseFile.toAbsolutePath()}"
            fun openSource() = HikariDataSource(HikariConfig().apply {
                this.jdbcUrl = jdbcUrl
                maximumPoolSize = 1
            })
            val source = openSource()
            try {
                val driver = source.asJdbcDriver()
                KeyReferenceDatabaseSqlite.Schema.create(driver)
                val historyStore = SqliteKeyReferenceStoreImpl(KeyReferenceDatabaseSqlite(driver), KeyReferenceHistoryCapability.DURABLE)
                val setup = newLocalWsca(keyReferenceStore = historyStore)
                val ref = setup.wsca
                    .createCredentialKey("wallet-discard", SecureComponentUsage.WALLET_CREDENTIAL_PROOF, SignatureAlgorithm.ECDSA_SHA256)
                    .let {
                        assertTrue(it.isOk, "createCredentialKey failed")
                        it.value
                    }
                val originalReference = historyStore.findAll(setup.tenantId).getOrThrow().single()
                val discarded = setup.wsca.discardCredentialKey("wallet-discard", ref)
                val signature = prepareAndSign(setup.wsca, "wallet-discard", ref, "must-fail".encodeToByteArray(), "test:discard")
                assertTrue(discarded.isOk, "discardCredentialKey failed: ${if (discarded.isErr) discarded.error else ""}")
                assertTrue(signature.isErr, "a discarded credential key must no longer sign")
                source.close()
                openSource().use { reopenedSource ->
                    val reopened = SqliteKeyReferenceStoreImpl(KeyReferenceDatabaseSqlite(reopenedSource.asJdbcDriver()), KeyReferenceHistoryCapability.DURABLE)
                    val history = reopened.findAllByAliasIncludingDeleted(setup.tenantId, originalReference.alias, originalReference.providerId).getOrThrow().single()
                    assertEquals(originalReference.id, history.id)
                    assertTrue(history.deletedAt != null, "destructive ownership history must survive database reopen")
                    assertTrue(reopened.findAllActiveByAlias(setup.tenantId, originalReference.alias, originalReference.providerId).getOrThrow().isEmpty())
                }
            } finally {
                source.close()
                Files.deleteIfExists(databaseFile)
            }
        }

    @Test
    fun ensureKeyRemainsIdempotentAlongsideCreateCredentialKey() =
        runTest {
            val wsca = newLocalWsca().wsca

            val stableFirst =
                wsca.ensureKey("wallet-stable", SecureComponentUsage.WALLET_CREDENTIAL_PROOF, SignatureAlgorithm.ECDSA_SHA256)
            // Minting fresh credential keys in between must not disturb ensureKey's stable identity.
            wsca.createCredentialKey("wallet-stable", SecureComponentUsage.WALLET_CREDENTIAL_PROOF, SignatureAlgorithm.ECDSA_SHA256)
            val stableSecond =
                wsca.ensureKey("wallet-stable", SecureComponentUsage.WALLET_CREDENTIAL_PROOF, SignatureAlgorithm.ECDSA_SHA256)

            assertTrue(stableFirst.isOk)
            assertTrue(stableSecond.isOk)
            assertEquals(stableFirst.value.keyRef, stableSecond.value.keyRef)
            assertEquals(stableFirst.value.publicKeyJwk, stableSecond.value.publicKeyJwk)
        }

    @Test
    fun oid4vciKeyAttestationUsesFinalNonceAndPublicJwkClaimsWithoutTs03Fields() =
        runTest {
            val profile = WalletUnitAttestationProfile.entries.firstOrNull { it.name == "OID4VCI_JWT" }
            assertNotNull(profile, "Final OID4VCI key attestation needs an explicit format distinct from TS03")
            val wsca = newLocalWsca().wsca
            val key = wsca.createCredentialKey(
                "wallet-final-ka", SecureComponentUsage.WALLET_CREDENTIAL_PROOF, SignatureAlgorithm.ECDSA_SHA256,
            ).getOrElse { error(it.toString()) }
            val result = wsca.attestKeys(
                KeyAttestationIssueRequest(
                    walletUnitId = "wallet-final-ka",
                    walletAccountId = "wallet-final-ka",
                    operationBinding = "test:ka:wallet-final-ka",
                    profile = profile,
                    attestedKeys = listOf(key),
                    audience = "https://issuer.example.com",
                    nonce = "fresh-issuer-nonce",
                ),
            ).getOrElse { error(it.toString()) }
            val parts = result.artifact.material.value.split('.')
            val header = Json.parseToJsonElement(parts[0].decodeFromBase64Url().decodeToString()).jsonObject
            val claims = Json.parseToJsonElement(parts[1].decodeFromBase64Url().decodeToString()).jsonObject
            assertEquals("key-attestation+jwt", header["typ"]?.jsonPrimitive?.content)
            assertEquals("fresh-issuer-nonce", claims["nonce"]?.jsonPrimitive?.content)
            assertNotNull(claims["iat"])
            assertNotNull(claims["exp"])
            assertFalse("c_nonce" in claims)
            val publicJwk = Json.parseToJsonElement(assertNotNull(key.publicKeyJwk)).jsonObject
            assertEquals(publicJwk, claims["attested_keys"]?.jsonArray?.single()?.jsonObject)
            assertFalse("keyId" in claims["attested_keys"]!!.jsonArray.single().jsonObject)
            assertFalse("d" in claims["attested_keys"]!!.jsonArray.single().jsonObject)
            assertFalse("key_storage" in claims, "Uncertified software must not claim ISO attack resistance")
            assertFalse("user_authentication" in claims)
        }

    @Test
    fun attestKeysProducesKeyAttestationJwtWithX5cAndAttestedKeys() =
        runTest {
            val wsca = newLocalWsca().wsca
            val holderKey =
                wsca
                    .createCredentialKey("wallet-attest", SecureComponentUsage.WALLET_CREDENTIAL_PROOF, SignatureAlgorithm.ECDSA_SHA256)
                    .let {
                        assertTrue(it.isOk, "createCredentialKey failed")
                        it.value
                    }

            val result =
                wsca.attestKeys(
                    KeyAttestationIssueRequest(
                        walletUnitId = "wallet-attest",
                        walletAccountId = "wallet-attest",
                        operationBinding = "test:ka:wallet-attest",
                        profile = WalletUnitAttestationProfile.TS03_JWT,
                        attestedKeys = listOf(holderKey),
                        signer =
                            WalletProviderAttestationSignerRef(
                                signerId = "wallet-attest-signer",
                                issuer = "https://wallet-provider.example",
                                signerProfile = "LOCAL_EVALUATION",
                                certificateChain = listOf("leaf-cert", "intermediate-cert"),
                            ),
                        audience = "https://issuer.example.com",
                        nonce = "nonce-1",
                    ),
                )

            assertTrue(result.isOk, "attestKeys failed: ${if (result.isErr) result.error else ""}")
            val compact = result.value.artifact.material.value
            val parts = compact.split('.')
            assertEquals(3, parts.size, "key attestation must be a compact JWS")
            val header = Json.parseToJsonElement(parts[0].decodeFromBase64Url().decodeToString()).jsonObject
            val payload = Json.parseToJsonElement(parts[1].decodeFromBase64Url().decodeToString()).jsonObject

            assertEquals("key-attestation+jwt", header["typ"]?.jsonPrimitive?.content)
            assertEquals("ES256", header["alg"]?.jsonPrimitive?.content)
            assertEquals(2, header["x5c"]?.jsonArray?.size)
            assertEquals("nonce-1", payload["c_nonce"]?.jsonPrimitive?.content)
            assertEquals("https://issuer.example.com", payload["aud"]?.jsonPrimitive?.content)
            assertEquals(1, payload["attested_keys"]?.jsonArray?.size)
        }

    @Test
    fun createDpopProofSignsWithUnitKeyAndEmbedsPublicJwk() =
        runTest {
            val wsca = newLocalWsca().wsca
            val key =
                wsca
                    .ensureKey("wallet-dpop", SecureComponentUsage.WALLET_ATTESTATION, SignatureAlgorithm.ECDSA_SHA384)
                    .let {
                        assertTrue(it.isOk, "ensureKey failed")
                        it.value
                    }

            val result =
                wsca.createDpopProof(
                    WscaDpopProofRequest(
                        walletUnitId = "wallet-dpop",
                        operationBinding = "test:dpop",
                        keyRef = key,
                        httpMethod = "post",
                        httpUrl = "https://issuer.example/token?ignored=true#fragment",
                        nonce = "dpop-nonce",
                        accessToken = "access-token",
                    ),
                )

            assertTrue(result.isOk, "createDpopProof failed: ${if (result.isErr) result.error else ""}")
            val parts = result.value.proofJwt.split('.')
            assertEquals(3, parts.size, "DPoP proof must be a compact JWS")
            val header = Json.parseToJsonElement(parts[0].decodeFromBase64Url().decodeToString()).jsonObject
            val payload = Json.parseToJsonElement(parts[1].decodeFromBase64Url().decodeToString()).jsonObject

            assertEquals("dpop+jwt", header["typ"]?.jsonPrimitive?.content)
            assertEquals("ES384", header["alg"]?.jsonPrimitive?.content)
            assertNotNull(header["jwk"]?.jsonObject)
            assertEquals("POST", payload["htm"]?.jsonPrimitive?.content)
            assertEquals("https://issuer.example/token", payload["htu"]?.jsonPrimitive?.content)
            assertEquals("dpop-nonce", payload["nonce"]?.jsonPrimitive?.content)
            assertNotNull(payload["ath"]?.jsonPrimitive?.content)
            assertTrue(result.value.jwkThumbprint.isNotBlank())
        }

    /**
     * Seam-equivalent of the former `createDpopProofRequiresInjectedOauth2DpopCommand`: with the
     * DPoP command dependency gone (assembly+signing is always available via
     * [DpopProofAssembly] + a [com.sphereon.wallet.wscd.Wscd]), the realistic failure mode is a key
     * reference the WSCD never provisioned - e.g. a caller that skipped [LocalWsca.ensureKey].
     */
    @Test
    fun createDpopProofFailsWhenKeyWasNeverProvisioned() =
        runTest {
            val wsca = newLocalWsca().wsca
            val fakeJwk =
                Jwk(
                    kty = JwaKeyType.EC,
                    crv = JwaCurve.P_256,
                    x = "fake-x",
                    y = "fake-y",
                )
            val neverProvisioned =
                WalletAttestedKeyRef(
                    keyId = "unprovisioned-key",
                    algorithm = "ES256",
                    publicKeyJwk = Json.encodeToString(Jwk.serializer(), fakeJwk),
                    keyRef = "wallet-units/wallet-dpop-missing-key/wallet_attestation/es256",
                    walletUnitId = "wallet-dpop-missing-key",
                )

            val result =
                wsca.createDpopProof(
                    WscaDpopProofRequest(
                        walletUnitId = "wallet-dpop-missing-key",
                        operationBinding = "test:dpop:missing-key",
                        keyRef = neverProvisioned,
                        httpMethod = "POST",
                        httpUrl = "https://issuer.example/token",
                    ),
                )

            assertTrue(result.isErr, "createDpopProof must fail for a key the WSCD never provisioned")
            assertEquals("WALLET_WSCD_KEY_NOT_PROVISIONED", result.error.code)
        }

    @Test
    fun clientAttestationDoesNotPublishInternalWalletEvidenceAndUsesFreshJti() = runTest {
        val wsca = newLocalWsca().wsca
        val key = wsca.ensureKey("private-unit-1", SecureComponentUsage.OAUTH_CLIENT_AUTHENTICATION, SignatureAlgorithm.ECDSA_SHA256)
            .getOrElse { error(it.toString()) }
        val request = WscaClientAttestationAuthRequest(
            walletUnitId = "private-unit-1", walletAccountId = "private-account-1",
            operationBinding = "private-operation-1", clientId = "shared-wallet-implementation",
            audience = "https://issuer-one.example", clientInstanceKey = key,
            walletName = "VDX Test Wallet", walletVersion = "1.0.0",
            signer = WalletProviderAttestationSignerRef(
                signerId = "provider-signer", issuer = "https://wallet-provider.example",
                signerProfile = "LOCAL_EVALUATION", certificateChain = listOf("leaf-only"),
            ),
            evidence = mapOf("walletUnitId" to "private-unit-1", "operationBinding" to "private-operation-1"),
        )
        fun payload(jwt: String) = Json.parseToJsonElement(jwt.split('.')[1].decodeFromBase64Url().decodeToString()).jsonObject
        val first = wsca.createClientAttestationAuth(request).getOrElse { error(it.toString()) }
        val second = wsca.createClientAttestationAuth(request.copy(audience = "https://issuer-two.example"))
            .getOrElse { error(it.toString()) }
        val firstClaims = payload(first.clientAttestationJwt)
        assertEquals("shared-wallet-implementation", firstClaims["sub"]?.jsonPrimitive?.content)
        assertFalse(firstClaims.toString().contains("private-unit-1"))
        assertFalse(firstClaims.toString().contains("private-account-1"))
        assertFalse(firstClaims.toString().contains("private-operation-1"))
        assertFalse(firstClaims["jti"] == payload(second.clientAttestationJwt)["jti"])
    }

    @Test
    fun createClientAttestationAuthProducesAttestationAndPopHeaderPair() =
        runTest {
            val wsca = newLocalWsca().wsca
            val clientInstanceKey =
                wsca
                    .ensureKey("wallet-client-auth", SecureComponentUsage.OAUTH_CLIENT_AUTHENTICATION, SignatureAlgorithm.ECDSA_SHA512)
                    .let {
                        assertTrue(it.isOk, "ensureKey failed")
                        it.value
                    }

            val result =
                wsca.createClientAttestationAuth(
                    WscaClientAttestationAuthRequest(
                        walletUnitId = "wallet-client-auth",
                        operationBinding = "test:client-attestation-auth",
                        walletAccountId = "wallet-client-auth",
                        clientId = "wallet-client",
                        audience = "https://issuer.example/token",
                        clientInstanceKey = clientInstanceKey,
                        walletName = "VDX Test Wallet",
                        walletVersion = "1.0.0",
                        signer =
                            WalletProviderAttestationSignerRef(
                                signerId = "wallet-client-auth-signer",
                                issuer = "https://wallet-provider.example",
                                signingAlgorithm = "ES384",
                                signerProfile = "LOCAL_EVALUATION",
                                certificateChain = listOf("leaf-cert"),
                            ),
                        challenge = "challenge-1",
                    ),
                )

            assertTrue(result.isOk, "createClientAttestationAuth failed: ${if (result.isErr) result.error else ""}")
            val attestationParts = result.value.clientAttestationJwt.split('.')
            val popParts = result.value.clientAttestationPopJwt.split('.')
            assertEquals(3, attestationParts.size, "client attestation must be a compact JWS")
            assertEquals(3, popParts.size, "client attestation PoP must be a compact JWS")

            val attestationHeader = Json.parseToJsonElement(attestationParts[0].decodeFromBase64Url().decodeToString()).jsonObject
            val attestationPayload = Json.parseToJsonElement(attestationParts[1].decodeFromBase64Url().decodeToString()).jsonObject
            val popHeader = Json.parseToJsonElement(popParts[0].decodeFromBase64Url().decodeToString()).jsonObject
            val popPayload = Json.parseToJsonElement(popParts[1].decodeFromBase64Url().decodeToString()).jsonObject

            assertEquals("oauth-client-attestation+jwt", attestationHeader["typ"]?.jsonPrimitive?.content)
            assertEquals("ES384", attestationHeader["alg"]?.jsonPrimitive?.content)
            assertEquals(1, attestationHeader["x5c"]?.jsonArray?.size)
            assertEquals("https://wallet-provider.example", attestationPayload["iss"]?.jsonPrimitive?.content)
            assertEquals("wallet-client", attestationPayload["sub"]?.jsonPrimitive?.content)
            assertEquals("VDX Test Wallet", attestationPayload["wallet_name"]?.jsonPrimitive?.content)
            assertNotNull(attestationPayload["cnf"]?.jsonObject?.get("jwk")?.jsonObject)

            assertEquals("oauth-client-attestation-pop+jwt", popHeader["typ"]?.jsonPrimitive?.content)
            assertEquals("ES512", popHeader["alg"]?.jsonPrimitive?.content)
            assertEquals("wallet-client", popPayload["iss"]?.jsonPrimitive?.content)
            assertEquals("https://issuer.example/token", popPayload["aud"]?.jsonPrimitive?.content)
            assertEquals("challenge-1", popPayload["challenge"]?.jsonPrimitive?.content)
            assertTrue(result.value.clientInstanceJwkThumbprint.isNotBlank())
        }

    @Test
    fun createClientAttestationAuthUsesConfiguredWalletProviderSignerForAdvertisedX5c() =
        runTest {
            val expectedSignature = byteArrayOf(1, 3, 3, 7)
            var capturedRequest: WalletAttestationSigningRequest? = null
            val resolver =
                object : WalletProviderAttestationSignerResolver {
                    override suspend fun resolve(signer: WalletProviderAttestationSignerRef) =
                        Ok(
                            object : WalletAttestationSigner {
                                override suspend fun sign(request: WalletAttestationSigningRequest) =
                                    Ok(
                                        WalletAttestationSigningResult(
                                            signature = expectedSignature,
                                            algorithm = request.algorithm,
                                            signerProfile = request.signerProfile,
                                            signerId = request.signerId,
                                            x5c = request.x5c,
                                            keyId = request.keyId,
                                        ),
                                    ).also { capturedRequest = request }
                            },
                        )
                }
            val wsca = newLocalWsca(signerResolver = resolver).wsca
            val clientInstanceKey =
                wsca.ensureKey("wallet-provider-signer", SecureComponentUsage.WALLET_ATTESTATION, SignatureAlgorithm.ECDSA_SHA256).value
            val signerRef =
                WalletProviderAttestationSignerRef(
                    signerId = "production-wallet-provider",
                    issuer = "https://wallet-provider.example",
                    keyId = "wallet-provider-x5c-key",
                    signingAlgorithm = "ES256",
                    signerProfile = WalletAttestationSignerProfile.REMOTE_WSCD.name,
                    certificateChain = listOf("production-leaf", "production-ca"),
                )

            val result =
                wsca.createClientAttestationAuth(
                    WscaClientAttestationAuthRequest(
                        walletUnitId = "wallet-provider-signer",
                        operationBinding = "test:configured-wallet-provider-signer",
                        walletAccountId = "wallet-provider-signer",
                        clientId = "wallet-client",
                        audience = "https://issuer.example/token",
                        clientInstanceKey = clientInstanceKey,
                        walletName = "VDX Test Wallet",
                        walletVersion = "1.0.0",
                        signer = signerRef,
                    ),
                )

            assertTrue(result.isOk, "createClientAttestationAuth failed: ${if (result.isErr) result.error else ""}")
            val parts = result.value.clientAttestationJwt.split('.')
            assertContentEquals(expectedSignature, parts[2].decodeFromBase64Url())
            val signingRequest = assertNotNull(capturedRequest)
            assertEquals("production-wallet-provider", signingRequest.signerId)
            assertEquals("wallet-provider-x5c-key", signingRequest.keyId)
            assertEquals(listOf("production-leaf", "production-ca"), signingRequest.x5c)
            assertContentEquals("${parts[0]}.${parts[1]}".encodeToByteArray(), signingRequest.signingInput)
        }

    @Test
    fun createClientAttestationAuthUsesTheConfiguredLocalWscdKey() =
        runTest {
            val wsca = newLocalWsca().wsca
            val walletUnitId = "wallet-local-wscd-provider-signer"
            val providerKey =
                wsca.ensureKey(
                    walletUnitId,
                    SecureComponentUsage.WALLET_ATTESTATION,
                    SignatureAlgorithm.ECDSA_SHA256,
                    keyAlias = "wallet-provider-x5c-key",
                ).value
            val clientInstanceKey =
                wsca.ensureKey(
                    walletUnitId,
                    SecureComponentUsage.WALLET_ATTESTATION,
                    SignatureAlgorithm.ECDSA_SHA256,
                    keyAlias = "wallet-client-instance-key",
                ).value

            val result =
                wsca.createClientAttestationAuth(
                    WscaClientAttestationAuthRequest(
                        walletUnitId = walletUnitId,
                        operationBinding = "test:local-wscd-wallet-provider-signer",
                        walletAccountId = walletUnitId,
                        clientId = "wallet-client",
                        audience = "https://issuer.example/token",
                        clientInstanceKey = clientInstanceKey,
                        walletName = "VDX Test Wallet",
                        walletVersion = "1.0.0",
                        signer =
                            WalletProviderAttestationSignerRef(
                                signerId = "local-wallet-provider",
                                issuer = "https://wallet-provider.example",
                                keyId = providerKey.keyRef,
                                signingAlgorithm = "ES256",
                                signerProfile = WalletAttestationSignerProfile.LOCAL_WSCD.name,
                                certificateChain = listOf("local-wscd-leaf"),
                            ),
                    ),
                )

            assertTrue(result.isOk, "LOCAL_WSCD client attestation failed: ${if (result.isErr) result.error else ""}")
            val parts = result.value.clientAttestationJwt.split('.')
            assertEquals(3, parts.size)
            val header = Json.parseToJsonElement(parts[0].decodeFromBase64Url().decodeToString()).jsonObject
            assertEquals("ES256", header["alg"]?.jsonPrimitive?.content)
            assertEquals("local-wscd-leaf", header["x5c"]?.jsonArray?.single()?.jsonPrimitive?.content)
        }

    @Test
    fun holderAttestKeysRejectsCrossUnitProviderAliasAndArbitraryIssuer() =
        runTest {
            val setup = newLocalWsca()
            val providerWalletUnitId = "wallet-provider-holder-surface"
            val holderWalletUnitId = "wallet-holder-holder-surface"
            val providerKey =
                setup.wsca
                    .ensureKey(
                        providerWalletUnitId,
                        SecureComponentUsage.WALLET_ATTESTATION,
                        SignatureAlgorithm.ECDSA_SHA256,
                        keyAlias = "provider-holder-surface-key",
                    )
                    .let {
                        assertTrue(it.isOk, "provider ensureKey failed")
                        it.value
                    }
            val holderKey =
                setup.wsca
                    .createCredentialKey(holderWalletUnitId, SecureComponentUsage.WALLET_CREDENTIAL_PROOF, SignatureAlgorithm.ECDSA_SHA256)
                    .let {
                        assertTrue(it.isOk, "holder createCredentialKey failed")
                        it.value
                    }

            val result =
                setup.wsca.attestKeys(
                    KeyAttestationIssueRequest(
                        walletUnitId = holderWalletUnitId,
                        walletAccountId = holderWalletUnitId,
                        operationBinding = "test:holder-cross-unit-provider-signing",
                        profile = WalletUnitAttestationProfile.TS03_JWT,
                        attestedKeys = listOf(holderKey),
                        signer =
                            WalletProviderAttestationSignerRef(
                                signerId = "arbitrary-provider",
                                issuer = "arbitrary-issuer",
                                keyId = providerKey.keyRef,
                                signingAlgorithm = "ES256",
                                signerProfile = WalletAttestationSignerProfile.LOCAL_WSCD.name,
                            ),
                        audience = "https://issuer.example.com",
                        nonce = "nonce-holder-cross-unit-provider-signing",
                    ),
                )

            assertTrue(result.isErr, "holder-facing attestKeys must reject a cross-unit provider alias")
            assertEquals("WALLET_WSCD_KEY_OWNER_MISMATCH", result.error.code)
        }

    // ---------------------------------------------------------------------------------------
    // LocalWsca.attestKeys derives honest KA claims from wscd.profile's capability metadata
    // and rejects caller-supplied claims that exceed it.
    // ---------------------------------------------------------------------------------------

    @Test
    fun attestKeysDerivesKeyStorageAndUserAuthenticationFromWscdProfileWhenOmitted() =
        runTest {
            val wsca = newLocalWsca().wsca
            val holderKey =
                wsca
                    .createCredentialKey("wallet-attest-defaults", SecureComponentUsage.WALLET_CREDENTIAL_PROOF, SignatureAlgorithm.ECDSA_SHA256)
                    .let {
                        assertTrue(it.isOk, "createCredentialKey failed")
                        it.value
                    }

            val result =
                wsca.attestKeys(
                    KeyAttestationIssueRequest(
                        walletUnitId = "wallet-attest-defaults",
                        walletAccountId = "wallet-attest-defaults",
                        operationBinding = "test:ka:wallet-attest-defaults",
                        profile = WalletUnitAttestationProfile.TS03_JWT,
                        attestedKeys = listOf(holderKey),
                        audience = "https://issuer.example.com",
                        nonce = "nonce-defaults",
                    ),
                )

            assertTrue(result.isOk, "attestKeys failed: ${if (result.isErr) result.error else ""}")
            val payload = decodeAttestationPayload(result.value.artifact.material.value)
            val keyStorage = payload["key_storage"]!!.jsonObject
            val userAuthentication = payload["user_authentication"]!!.jsonObject
            // No SoftwareWscd/LocalNativeWscd custody evidence is available for a fresh key
            // (SoftwareWscd.keyEvidence returns an empty map), so the merged "evidence" claim stays empty.
            // The claim VALUES below are WscdProfile.Software's honest ceiling: the lowest of every
            // profile - never an ISO 18045 tier, never non-exportable, never above LOW.
            assertEquals("none", keyStorage["security_level"]?.jsonPrimitive?.content)
            assertEquals("local_wscd", keyStorage["secure_component"]?.jsonPrimitive?.content)
            assertFalse(keyStorage["non_exportable"]!!.jsonPrimitive.content.toBoolean())
            assertEquals("low", userAuthentication["assurance_level"]?.jsonPrimitive?.content)
        }

    @Test
    fun attestKeysDerivesRemoteProfileClaimsWhenOmitted() =
        runTest {
            // An omitted request against a Remote-profile WSCD must derive the FULL production
            // claim set (the values KeyAttestationEvidenceEnforcer's production policy accepts),
            // proving the derivation is profile-driven rather than a Software-only default.
            val wsca = newLocalWsca(profile = WscdProfile.Remote).wsca
            val holderKey =
                wsca
                    .createCredentialKey("wallet-attest-remote-defaults", SecureComponentUsage.WALLET_CREDENTIAL_PROOF, SignatureAlgorithm.ECDSA_SHA256)
                    .let {
                        assertTrue(it.isOk, "createCredentialKey failed")
                        it.value
                    }

            val result =
                wsca.attestKeys(
                    KeyAttestationIssueRequest(
                        walletUnitId = "wallet-attest-remote-defaults",
                        walletAccountId = "wallet-attest-remote-defaults",
                        operationBinding = "test:ka:wallet-attest-remote-defaults",
                        profile = WalletUnitAttestationProfile.TS03_JWT,
                        attestedKeys = listOf(holderKey),
                        audience = "https://issuer.example.com",
                        nonce = "nonce-remote-defaults",
                    ),
                )

            assertTrue(result.isOk, "attestKeys failed: ${if (result.isErr) result.error else ""}")
            val payload = decodeAttestationPayload(result.value.artifact.material.value)
            val keyStorage = payload["key_storage"]!!.jsonObject
            val userAuthentication = payload["user_authentication"]!!.jsonObject
            assertEquals("iso_18045_high", keyStorage["security_level"]?.jsonPrimitive?.content)
            assertEquals("remote_wscd", keyStorage["secure_component"]?.jsonPrimitive?.content)
            assertTrue(keyStorage["non_exportable"]!!.jsonPrimitive.content.toBoolean())
            assertEquals("high", userAuthentication["assurance_level"]?.jsonPrimitive?.content)
        }

    @Test
    fun attestKeysRejectsKeyStorageSecurityLevelAboveWscdProfileCeiling() =
        runTest {
            val wsca = newLocalWsca().wsca
            val holderKey =
                wsca
                    .createCredentialKey("wallet-attest-level-ceiling", SecureComponentUsage.WALLET_CREDENTIAL_PROOF, SignatureAlgorithm.ECDSA_SHA256)
                    .let {
                        assertTrue(it.isOk, "createCredentialKey failed")
                        it.value
                    }

            val result =
                wsca.attestKeys(
                    KeyAttestationIssueRequest(
                        walletUnitId = "wallet-attest-level-ceiling",
                        walletAccountId = "wallet-attest-level-ceiling",
                        operationBinding = "test:ka:wallet-attest-level-ceiling",
                        profile = WalletUnitAttestationProfile.TS03_JWT,
                        attestedKeys = listOf(holderKey),
                        // Software's honest ceiling is WalletKeystoreSecurityLevel.NONE - claiming
                        // ISO_18045_HIGH is a lie this WSCD cannot back.
                        keystore =
                            WalletKeystoreRef(
                                id = "claimed-keystore",
                                namespace = "wallet-units",
                                securityLevel = WalletKeystoreSecurityLevel.ISO_18045_HIGH,
                                componentType = WalletSecureComponentType.LOCAL_WSCD,
                            ),
                        audience = "https://issuer.example.com",
                        nonce = "nonce-level-ceiling",
                    ),
                )

            assertTrue(result.isErr, "attestKeys must reject a key_storage.security_level claim above the profile's honest ceiling")
            assertEquals("WALLET_WSCD_KEY_ATTESTATION_CEILING_EXCEEDED", result.error.code)
        }

    @Test
    fun attestKeysRejectsKeyStorageSecureComponentThatDoesNotMatchWscdProfile() =
        runTest {
            val wsca = newLocalWsca().wsca
            val holderKey =
                wsca
                    .createCredentialKey("wallet-attest-component-ceiling", SecureComponentUsage.WALLET_CREDENTIAL_PROOF, SignatureAlgorithm.ECDSA_SHA256)
                    .let {
                        assertTrue(it.isOk, "createCredentialKey failed")
                        it.value
                    }

            val result =
                wsca.attestKeys(
                    KeyAttestationIssueRequest(
                        walletUnitId = "wallet-attest-component-ceiling",
                        walletAccountId = "wallet-attest-component-ceiling",
                        operationBinding = "test:ka:wallet-attest-component-ceiling",
                        profile = WalletUnitAttestationProfile.TS03_JWT,
                        attestedKeys = listOf(holderKey),
                        // secure_component has no ordering (WalletSecureComponentType is categorical):
                        // any value other than the profile's own is rejected, even one that "sounds"
                        // more secure than the honest NONE security level claimed alongside it.
                        keystore =
                            WalletKeystoreRef(
                                id = "claimed-keystore",
                                namespace = "wallet-units",
                                securityLevel = WalletKeystoreSecurityLevel.NONE,
                                componentType = WalletSecureComponentType.REMOTE_WSCD,
                            ),
                        audience = "https://issuer.example.com",
                        nonce = "nonce-component-ceiling",
                    ),
                )

            assertTrue(result.isErr, "attestKeys must reject a key_storage.secure_component claim that does not match the profile")
            assertEquals("WALLET_WSCD_KEY_ATTESTATION_CEILING_EXCEEDED", result.error.code)
        }

    @Test
    fun attestKeysRejectsNonExportableTrueClaimAboveWscdProfileCeiling() =
        runTest {
            val wsca = newLocalWsca().wsca
            val holderKey =
                wsca
                    .createCredentialKey("wallet-attest-export-ceiling", SecureComponentUsage.WALLET_CREDENTIAL_PROOF, SignatureAlgorithm.ECDSA_SHA256)
                    .let {
                        assertTrue(it.isOk, "createCredentialKey failed")
                        it.value
                    }

            val result =
                wsca.attestKeys(
                    KeyAttestationIssueRequest(
                        walletUnitId = "wallet-attest-export-ceiling",
                        walletAccountId = "wallet-attest-export-ceiling",
                        operationBinding = "test:ka:wallet-attest-export-ceiling",
                        profile = WalletUnitAttestationProfile.TS03_JWT,
                        attestedKeys = listOf(holderKey),
                        privateKeyProtection = WalletPrivateKeyProtectionEvidence(nonExportable = true, protectedByUserAuthentication = false),
                        audience = "https://issuer.example.com",
                        nonce = "nonce-export-ceiling",
                    ),
                )

            assertTrue(result.isErr, "attestKeys must reject a non_exportable=true claim above the profile's honest ceiling")
            assertEquals("WALLET_WSCD_KEY_ATTESTATION_CEILING_EXCEEDED", result.error.code)
        }

    @Test
    fun attestKeysRejectsUserAuthenticationAssuranceLevelAboveWscdProfileCeiling() =
        runTest {
            val wsca = newLocalWsca().wsca
            val holderKey =
                wsca
                    .createCredentialKey("wallet-attest-auth-ceiling", SecureComponentUsage.WALLET_CREDENTIAL_PROOF, SignatureAlgorithm.ECDSA_SHA256)
                    .let {
                        assertTrue(it.isOk, "createCredentialKey failed")
                        it.value
                    }

            val result =
                wsca.attestKeys(
                    KeyAttestationIssueRequest(
                        walletUnitId = "wallet-attest-auth-ceiling",
                        walletAccountId = "wallet-attest-auth-ceiling",
                        operationBinding = "test:ka:wallet-attest-auth-ceiling",
                        profile = WalletUnitAttestationProfile.TS03_JWT,
                        attestedKeys = listOf(holderKey),
                        userAuthentication = WalletUserAuthenticationEvidence(assuranceLevel = "high"),
                        audience = "https://issuer.example.com",
                        nonce = "nonce-auth-ceiling",
                    ),
                )

            assertTrue(result.isErr, "attestKeys must reject a user_authentication.assurance_level claim above the profile's honest ceiling")
            assertEquals("WALLET_WSCD_KEY_ATTESTATION_CEILING_EXCEEDED", result.error.code)
        }

    @Test
    fun attestKeysAcceptsKeyStorageAndUserAuthenticationBelowWscdProfileCeiling() =
        runTest {
            val wsca = newLocalWsca(profile = WscdProfile.Remote).wsca
            val holderKey =
                wsca
                    .createCredentialKey("wallet-attest-below-ceiling", SecureComponentUsage.WALLET_CREDENTIAL_PROOF, SignatureAlgorithm.ECDSA_SHA256)
                    .let {
                        assertTrue(it.isOk, "createCredentialKey failed")
                        it.value
                    }

            val result =
                wsca.attestKeys(
                    KeyAttestationIssueRequest(
                        walletUnitId = "wallet-attest-below-ceiling",
                        walletAccountId = "wallet-attest-below-ceiling",
                        operationBinding = "test:ka:wallet-attest-below-ceiling",
                        profile = WalletUnitAttestationProfile.TS03_JWT,
                        attestedKeys = listOf(holderKey),
                        // Remote's honest ceiling is ISO_18045_HIGH/REMOTE_WSCD/true/HIGH; every claim
                        // below is weaker than that ceiling and must be kept AS SUPPLIED, not silently
                        // upgraded to the ceiling.
                        keystore =
                            WalletKeystoreRef(
                                id = "claimed-keystore",
                                namespace = "wallet-units",
                                securityLevel = WalletKeystoreSecurityLevel.ISO_18045_MODERATE,
                                componentType = WalletSecureComponentType.REMOTE_WSCD,
                            ),
                        privateKeyProtection = WalletPrivateKeyProtectionEvidence(nonExportable = false, protectedByUserAuthentication = false),
                        userAuthentication = WalletUserAuthenticationEvidence(assuranceLevel = "substantial"),
                        audience = "https://issuer.example.com",
                        nonce = "nonce-below-ceiling",
                    ),
                )

            assertTrue(result.isOk, "attestKeys failed: ${if (result.isErr) result.error else ""}")
            val payload = decodeAttestationPayload(result.value.artifact.material.value)
            val keyStorage = payload["key_storage"]!!.jsonObject
            val userAuthentication = payload["user_authentication"]!!.jsonObject
            assertEquals("iso_18045_moderate", keyStorage["security_level"]?.jsonPrimitive?.content)
            assertEquals("remote_wscd", keyStorage["secure_component"]?.jsonPrimitive?.content)
            assertFalse(keyStorage["non_exportable"]!!.jsonPrimitive.content.toBoolean())
            assertEquals("substantial", userAuthentication["assurance_level"]?.jsonPrimitive?.content)
        }

    @Test
    fun attestKeysMergesWscdKeyEvidenceIntoKeyAttestationEvidence() =
        runTest {
            val deviceEvidence =
                mapOf(
                    "key_storage" to "device_keystore",
                    "hardware_backing_preference" to "required",
                    "key_attestation" to "unavailable-pending-signum",
                )
            val wsca = newLocalWsca(profile = WscdProfile.LocalNative, evidenceOverride = deviceEvidence).wsca
            val holderKey =
                wsca
                    .createCredentialKey("wallet-attest-evidence-merge", SecureComponentUsage.WALLET_CREDENTIAL_PROOF, SignatureAlgorithm.ECDSA_SHA256)
                    .let {
                        assertTrue(it.isOk, "createCredentialKey failed")
                        it.value
                    }

            val result =
                wsca.attestKeys(
                    KeyAttestationIssueRequest(
                        walletUnitId = "wallet-attest-evidence-merge",
                        walletAccountId = "wallet-attest-evidence-merge",
                        operationBinding = "test:ka:wallet-attest-evidence-merge",
                        profile = WalletUnitAttestationProfile.TS03_JWT,
                        attestedKeys = listOf(holderKey),
                        // A caller-supplied entry under a key the WSCD also reports must win: the WSCD's
                        // evidence is purely additive/enrichment, never an override of caller intent.
                        evidence = mapOf("key_storage" to "caller-asserted", "walletProviderRef" to "wallet-provider-1"),
                        audience = "https://issuer.example.com",
                        nonce = "nonce-evidence-merge",
                    ),
                )

            assertTrue(result.isOk, "attestKeys failed: ${if (result.isErr) result.error else ""}")
            val evidence = decodeAttestationPayload(result.value.artifact.material.value)["evidence"]!!.jsonObject
            assertEquals("caller-asserted", evidence["key_storage"]?.jsonPrimitive?.content)
            assertEquals("required", evidence["hardware_backing_preference"]?.jsonPrimitive?.content)
            assertEquals("unavailable-pending-signum", evidence["key_attestation"]?.jsonPrimitive?.content)
            assertEquals("wallet-provider-1", evidence["walletProviderRef"]?.jsonPrimitive?.content)
        }

    @Test
    fun attestKeysFailsWhenTheFirstAttestedKeyWasNeverProvisionedOnThisWscd() =
        runTest {
            val wsca = newLocalWsca().wsca
            val fakeJwk =
                Jwk(
                    kty = JwaKeyType.EC,
                    crv = JwaCurve.P_256,
                    x = "fake-x",
                    y = "fake-y",
                )
            val neverProvisioned =
                WalletAttestedKeyRef(
                    keyId = "unprovisioned-key",
                    algorithm = "ES256",
                    publicKeyJwk = Json.encodeToString(Jwk.serializer(), fakeJwk),
                    keyRef = "wallet-units/wallet-attest-missing-key/wallet_credential_proof/es256",
                    walletUnitId = "wallet-attest-missing-key",
                )

            val result =
                wsca.attestKeys(
                    KeyAttestationIssueRequest(
                        walletUnitId = "wallet-attest-missing-key",
                        walletAccountId = "wallet-attest-missing-key",
                        operationBinding = "test:ka:wallet-attest-missing-key",
                        profile = WalletUnitAttestationProfile.TS03_JWT,
                        attestedKeys = listOf(neverProvisioned),
                        audience = "https://issuer.example.com",
                        nonce = "nonce-missing-key",
                    ),
                )

            assertTrue(result.isErr, "attestKeys must fail when the WSCD cannot produce custody evidence for the attested key")
            assertEquals("WALLET_WSCD_KEY_NOT_PROVISIONED", result.error.code)
        }

    // ---------------------------------------------------------------------------------------
    // Outgoing-KA self-validation: attestKeys decodes the JWT it just signed
    // and re-checks it against the same invariants a verifier would enforce, rejecting any
    // caller-supplied expiresAt this WSCD cannot honestly stand behind - catching what the
    // request-shape validation at the top of attestKeys does not.
    // ---------------------------------------------------------------------------------------

    @Test
    fun attestKeysRejectsAnExpiresAtBeyondTheTwentyFourHourHonestTtlCeiling() =
        runTest {
            val wsca = newLocalWsca().wsca
            val holderKey =
                wsca
                    .createCredentialKey("wallet-attest-ttl-ceiling", SecureComponentUsage.WALLET_CREDENTIAL_PROOF, SignatureAlgorithm.ECDSA_SHA256)
                    .let {
                        assertTrue(it.isOk, "createCredentialKey failed")
                        it.value
                    }

            val result =
                wsca.attestKeys(
                    KeyAttestationIssueRequest(
                        walletUnitId = "wallet-attest-ttl-ceiling",
                        walletAccountId = "wallet-attest-ttl-ceiling",
                        operationBinding = "test:ka:wallet-attest-ttl-ceiling",
                        profile = WalletUnitAttestationProfile.TS03_JWT,
                        attestedKeys = listOf(holderKey),
                        audience = "https://issuer.example.com",
                        nonce = "nonce-ttl-ceiling",
                        // Mirrors LocalWalletProvider.issueInstanceAttestation's WIA ceiling: no KA-specific
                        // TTL is declared anywhere in the TS03 models, so 24h applies here too.
                        expiresAt = Clock.System.now() + 25.hours,
                    ),
                )

            assertTrue(result.isErr, "attestKeys must reject a key attestation lifetime beyond the honest 24h ceiling")
            assertEquals("WALLET_WSCD_KEY_ATTESTATION_SELF_VALIDATION_FAILED", result.error.code)
        }

    @Test
    fun attestKeysRejectsAnExpiresAtAtOrBeforeIssuance() =
        runTest {
            val wsca = newLocalWsca().wsca
            val holderKey =
                wsca
                    .createCredentialKey("wallet-attest-exp-not-after-iat", SecureComponentUsage.WALLET_CREDENTIAL_PROOF, SignatureAlgorithm.ECDSA_SHA256)
                    .let {
                        assertTrue(it.isOk, "createCredentialKey failed")
                        it.value
                    }

            val result =
                wsca.attestKeys(
                    KeyAttestationIssueRequest(
                        walletUnitId = "wallet-attest-exp-not-after-iat",
                        walletAccountId = "wallet-attest-exp-not-after-iat",
                        operationBinding = "test:ka:wallet-attest-exp-not-after-iat",
                        profile = WalletUnitAttestationProfile.TS03_JWT,
                        attestedKeys = listOf(holderKey),
                        audience = "https://issuer.example.com",
                        nonce = "nonce-exp-not-after-iat",
                        expiresAt = Clock.System.now() - 1.seconds,
                    ),
                )

            assertTrue(result.isErr, "attestKeys must reject an expiresAt that is not strictly after issuance")
            assertEquals("WALLET_WSCD_KEY_ATTESTATION_SELF_VALIDATION_FAILED", result.error.code)
        }

    @Test
    fun selfValidationRejectsACNonceThatDoesNotMatchTheRequestNonce() =
        runTest {
            val wsca = newLocalWsca().wsca as LocalWsca
            val now = Clock.System.now().epochSeconds
            val payload = """{"iat":$now,"exp":${now + 300},"c_nonce":"a-different-nonce"}"""
            val jwt =
                "eyJhbGciOiJFUzI1NiJ9." +
                    payload.encodeToByteArray().encodeToBase64Url() +
                    ".c2ln"

            val result = wsca.validateSelfIssuedKeyAttestation(jwt, expectedNonce = "the-request-nonce")

            assertTrue(result.isErr, "a c_nonce differing from the request nonce must fail self-validation")
            assertEquals("WALLET_WSCD_KEY_ATTESTATION_SELF_VALIDATION_FAILED", result.error.code)
        }

    @Test
    fun selfValidationRejectsAMalformedCompactJwt() =
        runTest {
            val wsca = newLocalWsca().wsca as LocalWsca

            val twoParts = wsca.validateSelfIssuedKeyAttestation("header.payload", expectedNonce = "n")
            assertTrue(twoParts.isErr, "a non-3-part string must fail self-validation")
            assertEquals("WALLET_WSCD_KEY_ATTESTATION_SELF_VALIDATION_FAILED", twoParts.error.code)

            val garbagePayload = wsca.validateSelfIssuedKeyAttestation("eyJhbGciOiJFUzI1NiJ9.!!!not-base64url!!!.c2ln", expectedNonce = "n")
            assertTrue(garbagePayload.isErr, "an undecodable payload must fail self-validation")
            assertEquals("WALLET_WSCD_KEY_ATTESTATION_SELF_VALIDATION_FAILED", garbagePayload.error.code)
        }

    private fun decodeAttestationPayload(compactJwt: String) =
        Json.parseToJsonElement(compactJwt.split('.')[1].decodeFromBase64Url().decodeToString()).jsonObject

    private suspend fun newLocalWsca(
        profile: WscdProfile = WscdProfile.Software,
        evidenceOverride: Map<String, String> = emptyMap(),
        userAuthenticator: WalletUserAuthenticator = successfulTestUserAuthenticator(),
        signerResolver: WalletProviderAttestationSignerResolver = LocalWalletProviderAttestationSignerResolver(),
        keyReferenceStore: KeyReferenceStore? = null,
    ): LocalWscaSetup {
        val sessionId = "wallet-unit-wsca-${Uuid.v4String()}"
        val app =
            createWalletAppGraph(
                application = "LocalWscaTest",
                appId = "com.sphereon.wallet.wsca-impl-test",
                profile = "test",
                version = "0.1.0",
            )
        keyReferenceStore?.let(app.keyReferenceStoreFactory::configureStoreForTesting)
        val userContext = app.userContextManager.getAnonymous()
        val session = userContext.sessionContextManager.createOrGetFromId(sessionId, principalType = com.sphereon.di.context.PrincipalType.USER)
        val kms = session.graph.asKeyManagerServiceGraph().keyManagerService
        val config =
            SoftwareKmsProviderConfig(
                id = "$sessionId-software-kms",
                cryptographyProvider = CryptographyProvider.Default.name,
            )
        val provider =
            (app as SoftwareKmsProviderFactoryImpl.Graph)
                .softwareKmsProvider
                .create(config, session.asCoreApiServiceGraph().serviceExecution)
        kms.registerProvider(provider, makeDefaultKms = true)
        val softwareWscd = SoftwareWscd(kms, providerBootstrap = KmsProviderBootstrap {})
        // ProfileOverrideWscd(softwareWscd, WscdProfile.Software, emptyMap()) behaves IDENTICALLY to
        // softwareWscd alone (SoftwareWscd.profile is already WscdProfile.Software and its
        // keyEvidence() already returns an empty map), so wrapping unconditionally keeps this fixture
        // to a single code path without changing any existing test's behavior.
        val wsca =
            LocalWsca(
                ProfileOverrideWscd(softwareWscd, profile, evidenceOverride),
                DpopProofAssembly(defaultSecureRandom()),
                userAuthenticator,
                signerResolver,
                defaultSecureRandom(),
            )
        return LocalWscaSetup(wsca = wsca, kms = kms, tenantId = session.asCoreApiServiceGraph().serviceExecution.sessionContext.context.tenant.tenantId)
    }

    private data class LocalWscaSetup(
        val wsca: LocalWsca,
        val kms: KeyManagerService,
        val tenantId: String,
    )

    private suspend fun prepareAndSign(
        wsca: Wsca,
        walletUnitId: String,
        keyRef: WalletAttestedKeyRef,
        signingInput: ByteArray,
        operationBinding: String,
    ) = wsca.run {
        val request = WscaSigningRequest(walletUnitId, keyRef, signingInput, operationBinding, audience = operationBinding)
        val prepared = prepareSign(request).getOrElse { return@run Err(it) }
        sign(prepared, request)
    }

    private fun successfulTestUserAuthenticator(): WalletUserAuthenticator =
        WalletUserAuthenticator { request ->
            Ok(
                ActivationProof(
                    kind = ActivationProofKind.LOCAL_USER_AUTH,
                    token = "test-local-user-auth",
                    digestBinding = request.digestBinding,
                    nonce = request.nonce,
                    evidence = mapOf("factor" to "pin"),
                ),
            )
        }

    /**
     * Test-only [Wscd] wrapper that fakes [profile] and [keyEvidence] while delegating every real
     * crypto operation (key generation, signing, deletion) to [delegate] - lets these tests exercise
     * [LocalWsca.attestKeys]'s honest, profile-derived KA claim/ceiling logic
     * against every [WscdProfile] variant without standing up a real LocalNativeWscd/RemoteWscd.
     * Safe because neither existing [Wscd] implementation's [Wscd.keyEvidence]/[Wscd.signDigest]
     * consult [WscdKeyHandle.profile] for key lookup - both key off [WscdKeyHandle.keyRef] only
     * (see SoftwareWscd/LocalNativeWscd `provisionedKeys[handle.keyRef]`), so a handle carrying a
     * different [WscdKeyHandle.profile] than what [delegate] originally provisioned still resolves.
     */
    private class ProfileOverrideWscd(
        private val delegate: Wscd,
        override val profile: WscdProfile,
        private val evidenceOverride: Map<String, String> = emptyMap(),
    ) : Wscd {
        override suspend fun generateKey(spec: WscdKeySpec) = delegate.generateKey(spec)

        override suspend fun generateFreshKey(spec: WscdKeySpec) = delegate.generateFreshKey(spec)

        override suspend fun signDigest(
            handle: WscdKeyHandle,
            digest: ByteArray,
            activation: ActivationProof,
        ) = delegate.signDigest(handle, digest, activation)

        override suspend fun deleteKey(handle: WscdKeyHandle) = delegate.deleteKey(handle)

        override suspend fun keyEvidence(handle: WscdKeyHandle) = delegate.keyEvidence(handle).map { it.copy(profile = profile, evidence = evidenceOverride) }
    }
}
