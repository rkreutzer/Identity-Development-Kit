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

package com.sphereon.mdoc

import com.sphereon.cbor.CborByteString
import com.sphereon.core.api.session.asCoreApiServiceGraph
import com.sphereon.crypto.core.CoseJoseKeyMappingService
import com.sphereon.crypto.core.CryptoServices
import com.sphereon.crypto.core.CoseCryptoServiceImpl
import com.sphereon.crypto.core.KeyInfo
import com.sphereon.crypto.core.KeyVisibility
import com.sphereon.crypto.core.cose.CoseAlgorithm
import com.sphereon.crypto.core.cose.CoseHeaderCbor
import com.sphereon.crypto.core.cose.CoseHeaderCborCodecImpl
import com.sphereon.crypto.core.cose.CoseKey
import com.sphereon.crypto.core.cose.CoseKeyCborCodecImpl
import com.sphereon.crypto.core.cose.CoseSign1
import com.sphereon.crypto.core.cose.CoseSign1Input
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.crypto.core.generic.DigestAlg
import com.sphereon.crypto.core.generic.hash
import com.sphereon.crypto.core.kms.command.SignatureEncoding
import com.sphereon.crypto.core.kms.asKeyManagerServiceGraph
import com.sphereon.crypto.kms.provider.software.SoftwareKmsProviderConfig
import com.sphereon.crypto.kms.provider.software.SoftwareKmsProviderFactoryImpl
import com.sphereon.mdoc.data.device.DeviceAuthentication
import com.sphereon.mdoc.data.device.DeviceItemsRequest
import com.sphereon.mdoc.data.device.DocRequest
import com.sphereon.mdoc.data.device.DocType
import com.sphereon.mdoc.data.device.Document
import com.sphereon.mdoc.data.device.IssuerSigned
import com.sphereon.mdoc.data.device.IssuerSignedNameSpaces
import com.sphereon.mdoc.data.mso.MobileSecurityObjectCborCodecImpl
import com.sphereon.mdoc.testutil.createMdocCryptoTestAppGraph
import kotlinx.coroutines.test.TestResult
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class MdocPreparedDeviceAuthenticationSigningTest {
    @Test
    fun managedDeviceKeyWithoutMsoKidUsesMatchingCustodyAndRejectsAnotherAlias(): TestResult =
        runTest {
            val app = createMdocCryptoTestAppGraph(this@MdocPreparedDeviceAuthenticationSigningTest)
            try {
                val context = app.userContextManager.getAnonymous()
                val session = context.sessionContextManager.createOrGetFromId(
                    "mdoc-no-kid-test", principalType = com.sphereon.di.context.PrincipalType.USER,
                )
                val execution = session.asCoreApiServiceGraph().serviceExecution
                val providerId = "mdoc-no-kid-provider"
                val provider = (app as SoftwareKmsProviderFactoryImpl.Graph).softwareKmsProvider.create(
                    SoftwareKmsProviderConfig(id = providerId), execution,
                )
                val kms = session.graph.asKeyManagerServiceGraph().keyManagerService
                kms.registerProvider(provider, makeDefaultKms = true)
                val holder = kms.generateKey(providerId = providerId, alias = "holder-a", alg = SignatureAlgorithm.ECDSA_SHA256)
                kms.generateKey(providerId = providerId, alias = "holder-b", alg = SignatureAlgorithm.ECDSA_SHA256)
                val publicInfo = CoseJoseKeyMappingService.toCoseKeyInfo(holder.joseToManagedKeyInfo(KeyVisibility.PUBLIC))
                val msoPublicKey = (requireNotNull(publicInfo.key) as CoseKey).copy(kid = null, original = null)
                val document = document(msoPublicKey)
                val request = DocRequest(
                    itemsRequest = DeviceItemsRequest(docType = document.docType, nameSpaces = emptyMap()), original = null,
                )
                val authentication = DeviceAuthentication.fromOid4vp(
                    clientId = "redirect_uri:https://verifier.example/response",
                    nonce = "no-kid-request-nonce", jwkThumbprint = null,
                    responseUri = "https://verifier.example/response", docType = document.docType,
                    deviceNamespaces = com.sphereon.mdoc.data.device.DeviceNameSpaces(emptyMap()),
                )
                val cose = (session.graph as CryptoServices.Graph).cryptoServices.cose as CoseCryptoServiceImpl
                val service = MdocSignServiceImpl(
                    cose, execution, MobileSecurityObjectCborCodecImpl(), SessionTranscriptCborCodecImpl(),
                )
                val selector = KeyInfo<CoseKey>(alias = holder.alias, providerId = providerId)
                val prepared = service.prepareDeviceAuthenticationSigning(
                    request, document, authentication, selector,
                ).getOrThrow()
                assertEquals(holder.alias, prepared.keyReference)
                val signature = kms.signDigest(
                    keyInfo = selector,
                    digest = hash(prepared.sigStructure, DigestAlg.SHA256),
                    signatureAlgorithm = SignatureAlgorithm.ECDSA_SHA256,
                    signatureEncoding = SignatureEncoding.RAW, requireX5Chain = false,
                )
                val completed = service.completeDeviceAuthenticationSigning(
                    request, document, authentication, selector, prepared, signature,
                )
                assertTrue(completed.isOk, "A matching custody key must work without an issuer-supplied kid: $completed")
                val immediate = service.deviceSignDocument(
                    request, document, authentication, selector,
                    unprotectedHeader = null, protectedHeader = null, requireDeviceX5Chain = false, macKeys = null,
                )
                assertTrue(immediate.deviceSigned?.deviceAuth?.deviceSignature != null)

                val unrelated = KeyInfo<CoseKey>(alias = "holder-b", providerId = providerId)
                val preparedForUnrelatedAlias = service.prepareDeviceAuthenticationSigning(
                    request, document, authentication, unrelated,
                ).getOrThrow()
                assertEquals("holder-b", preparedForUnrelatedAlias.keyReference)
                val unrelatedSignature = kms.signDigest(
                    keyInfo = unrelated,
                    digest = hash(preparedForUnrelatedAlias.sigStructure, DigestAlg.SHA256),
                    signatureAlgorithm = SignatureAlgorithm.ECDSA_SHA256,
                    signatureEncoding = SignatureEncoding.RAW, requireX5Chain = false,
                )
                val rejected = service.completeDeviceAuthenticationSigning(
                    request, document, authentication, unrelated, preparedForUnrelatedAlias, unrelatedSignature,
                )
                assertTrue(rejected.isErr, "A signature from a key that does not match the MSO must be rejected")
                assertFailsWith<IllegalArgumentException> {
                    service.deviceSignDocument(
                        request, document, authentication, unrelated,
                        unprotectedHeader = null, protectedHeader = null, requireDeviceX5Chain = false, macKeys = null,
                    )
                }
            } finally {
                app.destroy()
            }
        }

    @Test
    fun preparedSigningAcceptsOpaqueWscaReferenceWithoutKmsLookupAndRequiresAReference(): TestResult =
        runTest {
            val app = createMdocCryptoTestAppGraph(this@MdocPreparedDeviceAuthenticationSigningTest)
            try {
                val context = app.userContextManager.getAnonymous()
                val session = context.sessionContextManager.createOrGetFromId(
                    "mdoc-opaque-wsca-reference-test", principalType = com.sphereon.di.context.PrincipalType.USER,
                )
                val execution = session.asCoreApiServiceGraph().serviceExecution
                val providerId = "mdoc-opaque-reference-provider"
                val provider = (app as SoftwareKmsProviderFactoryImpl.Graph).softwareKmsProvider.create(
                    SoftwareKmsProviderConfig(id = providerId), execution,
                )
                val kms = session.graph.asKeyManagerServiceGraph().keyManagerService
                kms.registerProvider(provider, makeDefaultKms = true)
                val holder = kms.generateKey(providerId = providerId, alias = "real-managed-key", alg = SignatureAlgorithm.ECDSA_SHA256)
                val holderPublic = CoseJoseKeyMappingService.toCoseKeyInfo(holder.joseToManagedKeyInfo(KeyVisibility.PUBLIC))
                val msoPublicKey = (requireNotNull(holderPublic.key) as CoseKey).copy(kid = null, original = null)
                val document = document(msoPublicKey)
                val request = DocRequest(
                    itemsRequest = DeviceItemsRequest(docType = document.docType, nameSpaces = emptyMap()), original = null,
                )
                val authentication = DeviceAuthentication.fromOid4vp(
                    clientId = "redirect_uri:https://verifier.example/response",
                    nonce = "opaque-reference-request-nonce", jwkThumbprint = null,
                    responseUri = "https://verifier.example/response", docType = document.docType,
                    deviceNamespaces = com.sphereon.mdoc.data.device.DeviceNameSpaces(emptyMap()),
                )
                val service = MdocSignServiceImpl(
                    coseCryptoService = (session.graph as CryptoServices.Graph).cryptoServices.cose as CoseCryptoServiceImpl,
                    execution = execution,
                    mobileSecurityObjectCborCodec = MobileSecurityObjectCborCodecImpl(),
                    sessionTranscriptCborCodec = SessionTranscriptCborCodecImpl(),
                )
                val opaqueReference = KeyInfo<CoseKey>(alias = "opaque-wsca-reference")
                val prepared = service.prepareDeviceAuthenticationSigning(
                    request, document, authentication, opaqueReference,
                ).getOrThrow()
                assertEquals("opaque-wsca-reference", prepared.keyReference)
                assertTrue(prepared.publicDeviceKeyCbor.isNotEmpty())

                val signature = kms.signDigest(
                    keyInfo = KeyInfo<CoseKey>(alias = holder.alias, providerId = providerId),
                    digest = hash(prepared.sigStructure, DigestAlg.SHA256),
                    signatureAlgorithm = SignatureAlgorithm.ECDSA_SHA256,
                    signatureEncoding = SignatureEncoding.RAW, requireX5Chain = false,
                )
                assertTrue(
                    service.completeDeviceAuthenticationSigning(request, document, authentication, opaqueReference, prepared, signature).isOk,
                    "External signing over the MSO key may complete when the opaque reference is resolved by its secure component",
                )

                val missingReference = service.prepareDeviceAuthenticationSigning(
                    request, document, authentication, null,
                )
                assertTrue(missingReference.isErr, "An MSO without kid still requires a signer reference")
            } finally {
                app.destroy()
            }
        }

    @Test
    fun preparedDeviceAuthenticationUsesExactVerifiedSignatureAndRejectsChangedInputs(): TestResult =
        runTest {
            val app = createMdocCryptoTestAppGraph(this@MdocPreparedDeviceAuthenticationSigningTest)
            val context = app.userContextManager.getAnonymous()
            val session = context.sessionContextManager.createOrGetFromId(
                "mdoc-prepared-signing-test",
                principalType = com.sphereon.di.context.PrincipalType.USER,
            )
            app as SoftwareKmsProviderFactoryImpl.Graph
            val providerId = "mdoc-prepared-signing-provider"
            val provider = app.softwareKmsProvider.create(
                SoftwareKmsProviderConfig(
                    id = providerId,
                    cryptographyProvider = dev.whyoleg.cryptography.CryptographyProvider.Default.name,
                ),
                session.asCoreApiServiceGraph().serviceExecution,
            )
            val kms = session.graph.asKeyManagerServiceGraph().keyManagerService
            kms.registerProvider(provider, makeDefaultKms = true)
            val cose = (session.graph as CryptoServices.Graph).cryptoServices.cose as CoseCryptoServiceImpl
            val holderA = kms.generateKey(providerId = providerId, alias = "mdoc-prepared-holder-a", alg = SignatureAlgorithm.ECDSA_SHA256)
            val holderB = kms.generateKey(providerId = providerId, alias = "mdoc-prepared-holder-b", alg = SignatureAlgorithm.ECDSA_SHA256)
            val publicA = CoseJoseKeyMappingService.toCoseKeyInfo(holderA.joseToManagedKeyInfo(KeyVisibility.PUBLIC))
            val publicB = CoseJoseKeyMappingService.toCoseKeyInfo(holderB.joseToManagedKeyInfo(KeyVisibility.PUBLIC))
            val publicKeyA = requireNotNull(publicA.key) as CoseKey
            val selectedKey = KeyInfo<CoseKey>(alias = holderA.alias, kid = holderA.kid, providerId = providerId)
            val document = document(publicKeyA)
            val docType = document.docType
            val request = DocRequest(
                itemsRequest = DeviceItemsRequest(docType = docType, nameSpaces = emptyMap()),
                original = null,
            )
            val authentication = DeviceAuthentication.fromOid4vp(
                clientId = "did:jwk:holder-test",
                nonce = "request-nonce-one",
                jwkThumbprint = null,
                responseUri = "https://verifier.example/response",
                docType = docType,
                deviceNamespaces = com.sphereon.mdoc.data.device.DeviceNameSpaces(emptyMap()),
            )
            val keyCodec = CoseKeyCborCodecImpl()

            val prepared = MdocSignServiceImpl(
                coseCryptoService = cose,
                execution = session.asCoreApiServiceGraph().serviceExecution,
                mobileSecurityObjectCborCodec = MobileSecurityObjectCborCodecImpl(),
                sessionTranscriptCborCodec = SessionTranscriptCborCodecImpl(),
            ).prepareDeviceAuthenticationSigning(
                request = request,
                document = document,
                deviceAuthentication = authentication,
                deviceKeyInfo = selectedKey,
                protectedHeader = CoseHeaderCbor(alg = CoseAlgorithm.ES256),
            ).getOrThrow()

            // CoseKey.toPublicKey() clears the decoded private fields but retains `original`.
            // The COSE codec prefers `original` when encoding, so the prepared snapshot must
            // explicitly clear it before serializing the validated public point.
            val privateSourceEncoding = keyCodec.encode(
                publicKeyA.copy(d = CborByteString(byteArrayOf(11, 12, 13)), original = null),
            ).getOrThrow()
            val privateOriginalDocument = document(publicKeyA.copy(original = privateSourceEncoding))
            val preparedFromPrivateOriginal = MdocSignServiceImpl(
                coseCryptoService = cose,
                execution = session.asCoreApiServiceGraph().serviceExecution,
                mobileSecurityObjectCborCodec = MobileSecurityObjectCborCodecImpl(),
                sessionTranscriptCborCodec = SessionTranscriptCborCodecImpl(),
            ).prepareDeviceAuthenticationSigning(
                request = request,
                document = privateOriginalDocument,
                deviceAuthentication = authentication,
                deviceKeyInfo = selectedKey,
                protectedHeader = CoseHeaderCbor(alg = CoseAlgorithm.ES256),
            ).getOrThrow()
            val preparedFromPrivateOriginalKey = keyCodec.decode(preparedFromPrivateOriginal.publicDeviceKeyCbor).getOrThrow().value
            assertFalse(hasPrivateKeyMaterial(preparedFromPrivateOriginalKey), "A private original encoding must not survive public-key conversion")
            assertContentEquals(
                keyCodec.encode(publicKeyA.copy(original = null)).getOrThrow(),
                preparedFromPrivateOriginal.publicDeviceKeyCbor,
                "The snapshot must encode the public MSO key structure, not its retained original bytes",
            )

            assertEquals("mdoc-prepared-holder-a", prepared.keyReference)
            assertEquals(CoseAlgorithm.ES256, prepared.algorithm)
            assertTrue(prepared.sessionTranscriptCbor.isNotEmpty())
            assertTrue(prepared.sigStructure.isNotEmpty())
            val encodedPublicKey = prepared.publicDeviceKeyCbor
            val decodedPublicKey = keyCodec.decode(encodedPublicKey).getOrThrow().value
            assertFalse(hasPrivateKeyMaterial(decodedPublicKey), "Prepared snapshots must contain only public key material")
            assertContentEquals(encodedPublicKey, keyCodec.encode(decodedPublicKey.copy(original = null)).getOrThrow())
            val encodedSnapshot = Json.encodeToString(PreparedMdocDeviceAuthenticationSigning.serializer(), prepared)
            val restoredSnapshot = Json.decodeFromString(PreparedMdocDeviceAuthenticationSigning.serializer(), encodedSnapshot)
            assertContentEquals(prepared.protectedHeaderCbor, restoredSnapshot.protectedHeaderCbor)
            assertEquals(prepared.unprotectedHeaderCbor, restoredSnapshot.unprotectedHeaderCbor)
            assertContentEquals(encodedPublicKey, restoredSnapshot.publicDeviceKeyCbor)
            assertContentEquals(prepared.sigStructure, restoredSnapshot.sigStructure)

            val signingKey = MdocSignServiceImpl.getDeviceSigningKeyInfo(
                keyInfo = selectedKey,
                mso = mso(publicKeyA),
            )
            val genuineSignature = kms.signDigest(
                keyInfo = signingKey,
                digest = hash(prepared.sigStructure, DigestAlg.SHA256),
                signatureAlgorithm = SignatureAlgorithm.ECDSA_SHA256,
                signatureEncoding = SignatureEncoding.RAW,
                requireX5Chain = false,
            )
            val completed = MdocSignServiceImpl(
                coseCryptoService = cose,
                execution = session.asCoreApiServiceGraph().serviceExecution,
                mobileSecurityObjectCborCodec = MobileSecurityObjectCborCodecImpl(),
                sessionTranscriptCborCodec = SessionTranscriptCborCodecImpl(),
            ).completeDeviceAuthenticationSigning(
                request = request,
                document = document,
                deviceAuthentication = authentication,
                deviceKeyInfo = selectedKey,
                prepared = restoredSnapshot,
                signature = genuineSignature,
                protectedHeader = CoseHeaderCbor(alg = CoseAlgorithm.ES256),
            ).getOrThrow()
            val completedSignature = requireNotNull(completed.deviceSigned?.deviceAuth?.deviceSignature)
            assertContentEquals(genuineSignature, completedSignature.signature.value)
            assertEquals(null, completedSignature.payload, "The mdoc DeviceAuth COSE signature is detached")

            val changedAuthentication = DeviceAuthentication.fromOid4vp(
                clientId = "did:jwk:holder-test",
                nonce = "request-nonce-two",
                jwkThumbprint = null,
                responseUri = "https://verifier.example/response",
                docType = docType,
                deviceNamespaces = com.sphereon.mdoc.data.device.DeviceNameSpaces(emptyMap()),
            )
            val changedTranscript = MdocSignServiceImpl(
                coseCryptoService = cose,
                execution = session.asCoreApiServiceGraph().serviceExecution,
                mobileSecurityObjectCborCodec = MobileSecurityObjectCborCodecImpl(),
                sessionTranscriptCborCodec = SessionTranscriptCborCodecImpl(),
            ).completeDeviceAuthenticationSigning(
                request = request,
                document = document,
                deviceAuthentication = changedAuthentication,
                deviceKeyInfo = selectedKey,
                prepared = prepared,
                signature = genuineSignature,
                protectedHeader = CoseHeaderCbor(alg = CoseAlgorithm.ES256),
            )
            assertTrue(changedTranscript.isErr, "A changed OID4VP transcript must be rejected before signature acceptance")

            val publicKeyB = requireNotNull(publicB.key) as CoseKey
            val changedKeySnapshot = prepared.copy(publicDeviceKeyCbor = keyCodec.encode(publicKeyB.copy(original = null)).getOrThrow())
            val changedKey = MdocSignServiceImpl(
                coseCryptoService = cose,
                execution = session.asCoreApiServiceGraph().serviceExecution,
                mobileSecurityObjectCborCodec = MobileSecurityObjectCborCodecImpl(),
                sessionTranscriptCborCodec = SessionTranscriptCborCodecImpl(),
            ).completeDeviceAuthenticationSigning(
                request = request,
                document = document,
                deviceAuthentication = authentication,
                deviceKeyInfo = selectedKey,
                prepared = changedKeySnapshot,
                signature = genuineSignature,
                protectedHeader = CoseHeaderCbor(alg = CoseAlgorithm.ES256),
            )
            assertTrue(changedKey.isErr, "A changed public device key must be rejected")

            val privateKeyBytes = keyCodec.encode(publicKeyA.copy(d = CborByteString(byteArrayOf(7, 8, 9)), original = null)).getOrThrow()
            assertTrue(keyCodec.decode(privateKeyBytes).getOrThrow().value.d != null, "The private-key fixture must actually encode a private d value")
            val privateKeySnapshot = prepared.copy(publicDeviceKeyCbor = privateKeyBytes)
            val privateKeyRejected = MdocSignServiceImpl(
                coseCryptoService = cose,
                execution = session.asCoreApiServiceGraph().serviceExecution,
                mobileSecurityObjectCborCodec = MobileSecurityObjectCborCodecImpl(),
                sessionTranscriptCborCodec = SessionTranscriptCborCodecImpl(),
            ).completeDeviceAuthenticationSigning(
                request = request,
                document = document,
                deviceAuthentication = authentication,
                deviceKeyInfo = selectedKey,
                prepared = privateKeySnapshot,
                signature = genuineSignature,
                protectedHeader = CoseHeaderCbor(alg = CoseAlgorithm.ES256),
            )
            assertTrue(privateKeyRejected.isErr, "Private COSE key material in a serialized snapshot must be rejected")

            val malformedKeySnapshot = prepared.copy(publicDeviceKeyCbor = byteArrayOf(0xFF.toByte()))
            val malformedKeyRejected = MdocSignServiceImpl(
                coseCryptoService = cose,
                execution = session.asCoreApiServiceGraph().serviceExecution,
                mobileSecurityObjectCborCodec = MobileSecurityObjectCborCodecImpl(),
                sessionTranscriptCborCodec = SessionTranscriptCborCodecImpl(),
            ).completeDeviceAuthenticationSigning(
                request = request,
                document = document,
                deviceAuthentication = authentication,
                deviceKeyInfo = selectedKey,
                prepared = malformedKeySnapshot,
                signature = genuineSignature,
                protectedHeader = CoseHeaderCbor(alg = CoseAlgorithm.ES256),
            )
            assertTrue(malformedKeyRejected.isErr, "Malformed serialized COSE public key must be rejected")

            val nonCanonicalKeySnapshot = prepared.copy(publicDeviceKeyCbor = encodeWithNonCanonicalMapHead(encodedPublicKey))
            val nonCanonicalBytes = nonCanonicalKeySnapshot.publicDeviceKeyCbor
            val decodedNonCanonical = keyCodec.decode(nonCanonicalBytes)
            assertFalse(decodedNonCanonical.isErr, "The regression must exercise a decodable but noncanonical COSE key")
            val decodedNonCanonicalKey = decodedNonCanonical.getOrThrow().value
            assertContentEquals(
                nonCanonicalBytes,
                keyCodec.encode(decodedNonCanonicalKey).getOrThrow(),
                "The codec preserves decoded original bytes, so the snapshot verifier must clear them before canonical re-encoding",
            )
            assertContentEquals(
                encodedPublicKey,
                keyCodec.encode(decodedNonCanonicalKey.copy(original = null)).getOrThrow(),
                "Clearing the retained original must produce canonical COSE_Key bytes",
            )
            val nonCanonicalKeyRejected = MdocSignServiceImpl(
                coseCryptoService = cose,
                execution = session.asCoreApiServiceGraph().serviceExecution,
                mobileSecurityObjectCborCodec = MobileSecurityObjectCborCodecImpl(),
                sessionTranscriptCborCodec = SessionTranscriptCborCodecImpl(),
            ).completeDeviceAuthenticationSigning(
                request = request,
                document = document,
                deviceAuthentication = authentication,
                deviceKeyInfo = selectedKey,
                prepared = nonCanonicalKeySnapshot,
                signature = genuineSignature,
                protectedHeader = CoseHeaderCbor(alg = CoseAlgorithm.ES256),
            )
            assertTrue(nonCanonicalKeyRejected.isErr, "Noncanonical serialized COSE public key must be rejected")

            val changedSigStructure = prepared.copy(
                sigStructure = prepared.sigStructure.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() },
            )
            val changedPreimage = MdocSignServiceImpl(
                coseCryptoService = cose,
                execution = session.asCoreApiServiceGraph().serviceExecution,
                mobileSecurityObjectCborCodec = MobileSecurityObjectCborCodecImpl(),
                sessionTranscriptCborCodec = SessionTranscriptCborCodecImpl(),
            ).completeDeviceAuthenticationSigning(
                request = request,
                document = document,
                deviceAuthentication = authentication,
                deviceKeyInfo = selectedKey,
                prepared = changedSigStructure,
                signature = genuineSignature,
                protectedHeader = CoseHeaderCbor(alg = CoseAlgorithm.ES256),
            )
            assertTrue(changedPreimage.isErr, "A changed serialized Sig_structure must be rejected")

            val changedProtectedHeader = prepared.copy(
                protectedHeaderCbor = CoseHeaderCborCodecImpl().encode(
                    CoseHeaderCbor(alg = CoseAlgorithm.ES256, kid = CborByteString(byteArrayOf(1, 2, 3))),
                ).getOrThrow(),
            )
            val changedHeader = MdocSignServiceImpl(
                coseCryptoService = cose,
                execution = session.asCoreApiServiceGraph().serviceExecution,
                mobileSecurityObjectCborCodec = MobileSecurityObjectCborCodecImpl(),
                sessionTranscriptCborCodec = SessionTranscriptCborCodecImpl(),
            ).completeDeviceAuthenticationSigning(
                request = request,
                document = document,
                deviceAuthentication = authentication,
                deviceKeyInfo = selectedKey,
                prepared = changedProtectedHeader,
                signature = genuineSignature,
                protectedHeader = CoseHeaderCbor(alg = CoseAlgorithm.ES256),
            )
            assertTrue(changedHeader.isErr, "A changed protected header must be rejected against independent expected headers")

            val changedUnprotectedHeader = prepared.copy(
                unprotectedHeaderCbor = CoseHeaderCborCodecImpl().encode(
                    CoseHeaderCbor(kid = CborByteString(byteArrayOf(4, 5, 6))),
                ).getOrThrow(),
            )
            val changedUnprotected = MdocSignServiceImpl(
                coseCryptoService = cose,
                execution = session.asCoreApiServiceGraph().serviceExecution,
                mobileSecurityObjectCborCodec = MobileSecurityObjectCborCodecImpl(),
                sessionTranscriptCborCodec = SessionTranscriptCborCodecImpl(),
            ).completeDeviceAuthenticationSigning(
                request = request,
                document = document,
                deviceAuthentication = authentication,
                deviceKeyInfo = selectedKey,
                prepared = changedUnprotectedHeader,
                signature = genuineSignature,
                protectedHeader = CoseHeaderCbor(alg = CoseAlgorithm.ES256),
            )
            assertTrue(changedUnprotected.isErr, "A changed unprotected header must be rejected against independent expected headers")

            val wrongDigestPayload = prepared.deviceAuthenticationPayload.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
            val wrongDigestSignature = cose.sign1<Any>(
                input = CoseSign1Input(
                    protectedHeader = CoseHeaderCbor(alg = CoseAlgorithm.ES256),
                    unprotectedHeader = null,
                    payload = CborByteString(wrongDigestPayload),
                ),
                keyInfo = signingKey,
                requireX5Chain = false,
            ).coseSign1.signature.value
            val invalidSignature = MdocSignServiceImpl(
                coseCryptoService = cose,
                execution = session.asCoreApiServiceGraph().serviceExecution,
                mobileSecurityObjectCborCodec = MobileSecurityObjectCborCodecImpl(),
                sessionTranscriptCborCodec = SessionTranscriptCborCodecImpl(),
            ).completeDeviceAuthenticationSigning(
                request = request,
                document = document,
                deviceAuthentication = authentication,
                deviceKeyInfo = selectedKey,
                prepared = prepared,
                signature = wrongDigestSignature,
                protectedHeader = CoseHeaderCbor(alg = CoseAlgorithm.ES256),
            )
            assertTrue(invalidSignature.isErr, "A signature valid only for a different digest must be rejected")

            val doubleHashedSignature = kms.signDigest(
                keyInfo = signingKey,
                digest = hash(hash(prepared.sigStructure, DigestAlg.SHA256), DigestAlg.SHA256),
                signatureAlgorithm = SignatureAlgorithm.ECDSA_SHA256,
                signatureEncoding = SignatureEncoding.RAW,
                requireX5Chain = false,
            )
            val doubleHashRejected = MdocSignServiceImpl(
                coseCryptoService = cose,
                execution = session.asCoreApiServiceGraph().serviceExecution,
                mobileSecurityObjectCborCodec = MobileSecurityObjectCborCodecImpl(),
                sessionTranscriptCborCodec = SessionTranscriptCborCodecImpl(),
            ).completeDeviceAuthenticationSigning(
                request = request,
                document = document,
                deviceAuthentication = authentication,
                deviceKeyInfo = selectedKey,
                prepared = prepared,
                signature = doubleHashedSignature,
                protectedHeader = CoseHeaderCbor(alg = CoseAlgorithm.ES256),
            )
            assertTrue(doubleHashRejected.isErr, "ECDSA signature over SHA-256(SHA-256(Sig_structure)) must be rejected")
        }

    private fun document(deviceKey: CoseKey): Document {
        val encodedMso = MobileSecurityObjectCborCodecImpl().encode(mso(deviceKey)).getOrThrow()
        val issuerAuth = CoseSign1<com.sphereon.mdoc.data.mso.MobileSecurityObject>(
            protectedHeader = CoseHeaderCbor(alg = CoseAlgorithm.ES256),
            unprotectedHeader = null,
            payload = CborByteString(encodedMso),
            signature = CborByteString(byteArrayOf(1)),
        )
        return Document(
            docType = DocType("org.iso.18013.5.1.mDL"),
            issuerSigned = IssuerSigned(nameSpaces = null as IssuerSignedNameSpaces?, issuerAuth = issuerAuth, original = null),
            deviceSigned = null,
            original = null,
        )
    }

    private fun hasPrivateKeyMaterial(key: CoseKey): Boolean =
        key.d != null || key.rsaP != null || key.rsaQ != null || key.rsaDP != null || key.rsaDQ != null || key.rsaQInv != null || key.additional != null

    private fun encodeWithNonCanonicalMapHead(encoded: ByteArray): ByteArray {
        val first = encoded.first().toInt() and 0xFF
        require(first in 0xA0..0xB7) { "Expected a canonical short CBOR map header" }
        val entries = (first - 0xA0).toByte()
        return byteArrayOf(0xB8.toByte(), entries) + encoded.copyOfRange(1, encoded.size)
    }

    private fun mso(deviceKey: CoseKey): com.sphereon.mdoc.data.mso.MobileSecurityObject =
        com.sphereon.mdoc.data.mso.MobileSecurityObject(
            digestAlgorithm = com.sphereon.mdoc.data.mso.DigestAlgorithm("SHA-256"),
            valueDigests = emptyMap(),
            deviceKeyInfo = com.sphereon.mdoc.data.mso.DeviceKeyInfo(deviceKey = deviceKey, original = null),
            docType = DocType("org.iso.18013.5.1.mDL"),
            validityInfo = com.sphereon.mdoc.data.mso.ValidityInfo(
                signed = com.sphereon.cbor.TDate("2026-08-29T00:00:00Z"),
                validFrom = com.sphereon.cbor.TDate("2026-08-29T00:00:00Z"),
                validUntil = com.sphereon.cbor.TDate("2027-08-29T00:00:00Z"),
            ),
            original = null,
        )
}
