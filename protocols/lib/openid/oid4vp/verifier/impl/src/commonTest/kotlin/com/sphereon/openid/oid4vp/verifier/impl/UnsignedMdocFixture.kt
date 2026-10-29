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

package com.sphereon.openid.oid4vp.verifier.impl

import com.sphereon.cbor.CborByteString
import com.sphereon.cbor.TDate
import com.sphereon.core.api.encodeToBase64Url
import com.sphereon.crypto.core.cose.CoseAlgorithm
import com.sphereon.crypto.core.cose.CoseCurve
import com.sphereon.crypto.core.cose.CoseHeaderCbor
import com.sphereon.crypto.core.cose.CoseKeyJson
import com.sphereon.crypto.core.cose.CoseKeyTypeEnum
import com.sphereon.crypto.core.cose.CoseSign1
import com.sphereon.mdoc.data.device.DataElementIdentifier
import com.sphereon.mdoc.data.device.DeviceResponse
import com.sphereon.mdoc.data.device.DeviceResponseCborCodecImpl
import com.sphereon.mdoc.data.device.DocType
import com.sphereon.mdoc.data.device.Document
import com.sphereon.mdoc.data.device.IssuerSigned
import com.sphereon.mdoc.data.device.IssuerSignedItem
import com.sphereon.mdoc.data.device.IssuerSignedItemCborCodecImpl
import com.sphereon.mdoc.data.device.NameSpace
import com.sphereon.mdoc.data.device.RandomValue
import com.sphereon.mdoc.data.mso.DeviceKeyInfo
import com.sphereon.mdoc.data.mso.DigestAlgorithm
import com.sphereon.mdoc.data.mso.MobileSecurityObject
import com.sphereon.mdoc.data.mso.MobileSecurityObjectCborCodecImpl
import com.sphereon.mdoc.data.mso.MsoVersion
import com.sphereon.mdoc.data.mso.ValidityInfo
import com.sphereon.mdoc.data.mso.DigestID

/** One issuer-signed data element of a fixture document. [value] is a String, Boolean, Long, ByteArray, Map or List. */
internal data class FixtureElement(
    val identifier: String,
    val value: Any,
)

internal data class FixtureDocument(
    val docType: String,
    val nameSpaces: Map<String, List<FixtureElement>>,
)

/**
 * A well-formed `DeviceResponse` in its OID4VP wire form (base64url of the CBOR), with a placeholder
 * issuer signature. Tests that use it replace the holder-binding and issuer-trust steps with stubs, so
 * only the structure matters here, and the real CBOR codecs build and read it.
 */
internal fun unsignedMdocPresentation(vararg documents: FixtureDocument): String {
    val itemCodec = IssuerSignedItemCborCodecImpl()
    val msoCodec = MobileSecurityObjectCborCodecImpl()
    val now = TDate("2025-01-20T12:00:00Z")
    var digest = 0u
    val builtDocuments =
        documents
            .map { document ->
                val mso =
                    MobileSecurityObject(
                        version = MsoVersion("1.0"),
                        digestAlgorithm = DigestAlgorithm("SHA-256"),
                        valueDigests = emptyMap(),
                        deviceKeyInfo =
                            DeviceKeyInfo(
                                deviceKey =
                                    CoseKeyJson
                                        .Builder()
                                        .withKty(CoseKeyTypeEnum.EC2)
                                        .withCrv(CoseCurve.P_256)
                                        .withX("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                                        .withY("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
                                        .build()
                                        .toCbor(),
                                keyAuthorizations = null,
                                keyInfo = null,
                                original = null,
                            ),
                        docType = DocType(document.docType),
                        validityInfo = ValidityInfo(signed = now, validFrom = now, validUntil = now, expectedUpdate = null),
                        original = null,
                    )
                val issuerAuth: CoseSign1<MobileSecurityObject> =
                    CoseSign1(
                        protectedHeader = CoseHeaderCbor(alg = CoseAlgorithm.ES256),
                        unprotectedHeader = CoseHeaderCbor(),
                        payload = CborByteString(msoCodec.encodeTag24(mso).getOrThrow()),
                        signature = CborByteString(ByteArray(64) { it.toByte() }),
                    )
                @Suppress("UNCHECKED_CAST")
                val nameSpaces =
                    document.nameSpaces.entries.associate { (nameSpace, elements) ->
                        NameSpace(nameSpace) to
                            elements
                                .map { element ->
                                    val item =
                                        IssuerSignedItem(
                                            digestID = DigestID(digest++),
                                            random = RandomValue(ByteArray(24) { 0x42.toByte() }),
                                            elementIdentifier = DataElementIdentifier(element.identifier),
                                            elementValue = element.value,
                                        )
                                    itemCodec.encodeItem(item as IssuerSignedItem<Any>).getOrThrow()
                                }.toTypedArray()
                    }
                Document(
                    docType = DocType(document.docType),
                    issuerSigned = IssuerSigned(nameSpaces = nameSpaces, issuerAuth = issuerAuth, original = null),
                    deviceSigned = null,
                    original = null,
                )
            }.toTypedArray()
    return DeviceResponseCborCodecImpl()
        .encode(DeviceResponse(documents = builtDocuments, original = null))
        .getOrThrow()
        .encodeToBase64Url()
}
