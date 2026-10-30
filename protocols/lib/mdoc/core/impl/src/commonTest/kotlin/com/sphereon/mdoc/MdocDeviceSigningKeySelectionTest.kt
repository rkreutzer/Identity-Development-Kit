/*
 * Copyright 2023-2026 Sphereon International B.V.
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
import com.sphereon.cbor.CborUInt
import com.sphereon.cbor.TDate
import com.sphereon.core.api.Encoding
import com.sphereon.core.api.session.asCoreApiServiceGraph
import com.sphereon.crypto.core.CoseJoseKeyMappingService
import com.sphereon.crypto.core.CryptoServices
import com.sphereon.crypto.core.KeyInfo
import com.sphereon.crypto.core.KeyVisibility
import com.sphereon.crypto.core.cose.CoseAlgorithm
import com.sphereon.crypto.core.cose.CoseCurve
import com.sphereon.crypto.core.cose.CoseHeaderCbor
import com.sphereon.crypto.core.cose.CoseKey
import com.sphereon.crypto.core.cose.CoseKeyTypeEnum
import com.sphereon.crypto.core.cose.CoseSign1Input
import com.sphereon.crypto.core.generic.KeyTypeMapping
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.crypto.core.kms.asKeyManagerServiceGraph
import com.sphereon.mdoc.testutil.createMdocCryptoTestAppGraph
import com.sphereon.crypto.kms.provider.software.SoftwareKmsProviderConfig
import com.sphereon.crypto.kms.provider.software.SoftwareKmsProviderFactoryImpl
import com.sphereon.mdoc.data.device.DocType
import com.sphereon.mdoc.data.mso.DeviceKeyInfo
import com.sphereon.mdoc.data.mso.DigestAlgorithm
import com.sphereon.mdoc.data.mso.MobileSecurityObject
import com.sphereon.mdoc.data.mso.ValidityInfo
import dev.whyoleg.cryptography.CryptographyProvider
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

class MdocDeviceSigningKeySelectionTest {
    @Test
    fun `real managed device signing binds alias to the authenticated MSO kid`() =
        runTest {
            val app = createMdocCryptoTestAppGraph(this@MdocDeviceSigningKeySelectionTest)
            val context = app.userContextManager.getAnonymous()
            val session =
                context.sessionContextManager.createOrGetFromId(
                    "mdoc-managed-selector-test",
                    principalType = com.sphereon.di.context.PrincipalType.USER,
                )
            app as SoftwareKmsProviderFactoryImpl.Graph
            val providerId = "mdoc-managed-selector-provider"
            val provider =
                app.softwareKmsProvider.create(
                    SoftwareKmsProviderConfig(
                        id = providerId,
                        cryptographyProvider = CryptographyProvider.Default.name,
                    ),
                    session.asCoreApiServiceGraph().serviceExecution,
                )
            val kms = session.graph.asKeyManagerServiceGraph().keyManagerService
            kms.registerProvider(provider, makeDefaultKms = true)
            val cose = (session.graph as CryptoServices.Graph).cryptoServices.cose

            val keyA = kms.generateKey(providerId = providerId, alias = "mdoc-holder-a", alg = SignatureAlgorithm.ECDSA_SHA256)
            val keyB = kms.generateKey(providerId = providerId, alias = "mdoc-holder-b", alg = SignatureAlgorithm.ECDSA_SHA256)
            val publicA = keyA.joseToManagedKeyInfo(KeyVisibility.PUBLIC)
            val publicB = keyB.joseToManagedKeyInfo(KeyVisibility.PUBLIC)
            val cosePublicA = CoseJoseKeyMappingService.toCoseKeyInfo(publicA)
            val msoKey = requireNotNull(cosePublicA.key) as CoseKey
            val msoKid = requireNotNull(msoKey.kid).encodeValueTo(Encoding.UTF8)
            assertEquals(publicA.kid, msoKid)

            val selectedA =
                MdocSignServiceImpl.getDeviceSigningKeyInfo(
                    keyInfo = KeyInfo<CoseKey>(alias = publicA.alias, kid = msoKid, providerId = providerId),
                    mso = mso(msoKey),
                )
            val input =
                CoseSign1Input(
                    protectedHeader = CoseHeaderCbor(alg = CoseAlgorithm.ES256),
                    unprotectedHeader = null,
                    payload = CborByteString("mdoc device authentication".encodeToByteArray()),
                )
            val signed = cose.sign1<Any>(input = input, keyInfo = selectedA, requireX5Chain = false)
            val verified = cose.verify1(input = signed.coseSign1, keyInfo = cosePublicA, requireX5Chain = false)
            assertFalse(verified.error, "Device signature must verify with the MSO holder key A: ${verified.message}")

            val wrongAlias =
                MdocSignServiceImpl.getDeviceSigningKeyInfo(
                    keyInfo = KeyInfo<CoseKey>(alias = publicB.alias, kid = msoKid, providerId = providerId),
                    mso = mso(msoKey),
                )
            val mismatch = assertFailsWith<Exception> { cose.sign1<Any>(input, wrongAlias, requireX5Chain = false) }
            assertTrue(mismatch.message.orEmpty().contains("Managed signing key selector mismatch"))
            assertTrue(mismatch.message.orEmpty().contains("alias '${publicB.alias}'"))
            assertTrue(mismatch.message.orEmpty().contains("requested kid '$msoKid'"))
        }

    @Test
    fun `managed signing uses alias plus the raw UTF-8 MSO kid without inline public material`() {
        val result =
            MdocSignServiceImpl.getDeviceSigningKeyInfo(
                keyInfo =
                    KeyInfo<CoseKey>(
                        alias = "wallet-device-key",
                        providerId = "software",
                        keyVisibility = KeyVisibility.PRIVATE,
                    ),
                mso = mso(deviceKey()),
            )

        assertEquals("wallet-device-key", result.alias)
        assertEquals("software", result.providerId)
        assertEquals(DEVICE_KID, result.kid)
        assertNull(result.key, "Managed signing must not reattach the public-only key from the MSO")
        assertEquals(SignatureAlgorithm.ECDSA_SHA256, result.signatureAlgorithm)
        assertEquals(KeyTypeMapping.EC, result.keyType)
    }

    @Test
    fun `base64url text for the raw MSO kid is rejected rather than treated as an alias`() {
        val exception =
            assertFailsWith<IllegalArgumentException> {
                MdocSignServiceImpl.getDeviceSigningKeyInfo(
                    keyInfo = KeyInfo<CoseKey>(alias = "wallet-device-key", kid = "aG9sZGVyLWtleS0x"),
                    mso = mso(deviceKey()),
                )
            }

        assertEquals(
            "Device signing key kid 'aG9sZGVyLWtleS0x' does not match Mobile Security Object device key kid '$DEVICE_KID'",
            exception.message,
        )
    }

    @Test
    fun `managed signing without an MSO kid fails closed`() {
        val exception =
            assertFailsWith<IllegalArgumentException> {
                MdocSignServiceImpl.getDeviceSigningKeyInfo(
                    keyInfo = KeyInfo<CoseKey>(alias = "wallet-device-key"),
                    mso = mso(deviceKey(kid = null)),
                )
            }

        assertEquals(
            "Managed mdoc device signing without an MSO kid requires resolved public key material",
            exception.message,
        )
    }

    @Test
    fun `managed signing without an alias fails closed instead of selecting among provider keys`() {
        val exception =
            assertFailsWith<IllegalArgumentException> {
                MdocSignServiceImpl.getDeviceSigningKeyInfo(
                    keyInfo = KeyInfo<CoseKey>(kid = DEVICE_KID),
                    mso = mso(deviceKey()),
                )
            }

        assertEquals(
            "Managed mdoc device signing requires a non-blank key alias",
            exception.message,
        )
    }

    @Test
    fun `managed selection retains both alias and kid so multiple provider keys cannot fall back to first match`() {
        val result =
            MdocSignServiceImpl.getDeviceSigningKeyInfo(
                keyInfo =
                    KeyInfo<CoseKey>(
                        alias = "second-wallet-key",
                        kid = DEVICE_KID,
                        providerId = "software",
                    ),
                mso = mso(deviceKey()),
            )

        assertEquals("second-wallet-key", result.alias)
        assertEquals(DEVICE_KID, result.kid)
        assertNull(result.key)
    }

    @Test
    fun `inline holder key that differs from the authenticated MSO key fails closed`() {
        val differentKey = deviceKey().copy(x = CborByteString(ByteArray(32) { 0x42.toByte() }))

        val exception =
            assertFailsWith<IllegalArgumentException> {
                MdocSignServiceImpl.getDeviceSigningKeyInfo(
                    keyInfo = KeyInfo(kid = DEVICE_KID, key = differentKey),
                    mso = mso(deviceKey()),
                )
            }

        assertEquals(
            "Supplied mdoc device key does not match Mobile Security Object device key",
            exception.message,
        )
    }

    private fun deviceKey(kid: String? = DEVICE_KID): CoseKey =
        CoseKey(
            kty = CborUInt(CoseKeyTypeEnum.EC2.value.toLong()),
            kid = kid?.encodeToByteArray()?.let(::CborByteString),
            alg = CborUInt(CoseAlgorithm.ES256.value.toLong()),
            crv = CborUInt(CoseCurve.P_256.value.toLong()),
            x = CborByteString(ByteArray(32) { 0x11.toByte() }),
            y = CborByteString(ByteArray(32) { 0x22.toByte() }),
        )

    private fun mso(deviceKey: CoseKey): MobileSecurityObject =
        MobileSecurityObject(
            digestAlgorithm = DigestAlgorithm("SHA-256"),
            valueDigests = emptyMap(),
            deviceKeyInfo = DeviceKeyInfo(deviceKey = deviceKey, original = null),
            docType = DocType("org.iso.18013.5.1.mDL"),
            validityInfo =
                ValidityInfo(
                    signed = TDate("2026-08-29T00:00:00Z"),
                    validFrom = TDate("2026-08-29T00:00:00Z"),
                    validUntil = TDate("2027-08-29T00:00:00Z"),
                ),
            original = null,
        )

    private companion object {
        const val DEVICE_KID = "holder-key-1"
    }
}
