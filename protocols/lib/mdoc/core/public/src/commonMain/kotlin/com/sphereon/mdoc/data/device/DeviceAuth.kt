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

package com.sphereon.mdoc.data.device

import com.sphereon.cbor.CborString
import com.sphereon.cbor.StringLabel
import com.sphereon.core.compat.JsExportCompat
import com.sphereon.crypto.core.cose.COSE_Sign1
import com.sphereon.crypto.core.cose.CoseMac0Cbor
import com.sphereon.mdoc.transfer.reader.Iso18013Oid4vpHandover
import com.sphereon.mdoc.transfer.reader.SessionTranscript
import com.sphereon.mdoc.oid4vp.Oid4vpDeviceAuthenticationContext
import com.sphereon.mdoc.oid4vp.toSessionTranscript
import com.sphereon.util.stringify
import kotlinx.serialization.Serializable
import kotlin.experimental.ExperimentalObjCName
import kotlin.js.JsName
import kotlin.js.JsStatic
import kotlin.jvm.JvmInline
import kotlin.jvm.JvmStatic
import kotlin.native.ObjCName

@JsExportCompat
@OptIn(ExperimentalObjCName::class)
@ObjCName("DeviceAuthType", exact = true)
enum class DeviceAuthType {
    SIGNATURE,
    MAC,
}

/**
 * Device MAC authentication value.
 *
 * ISO/IEC 18013-5 defines this field as a detached COSE_Mac0.  Older versions of this library
 * exposed a string wrapper and some deployed callers still construct that form, so the legacy
 * constructor and [toCborItem] remain available.  New code should use [CoseMac0Cbor] and the
 * codec in the mdoc implementation module; the common model never treats a legacy string as
 * authenticated data.
 */
@JsExportCompat
class DeviceMac private constructor(
    val coseMac0: CoseMac0Cbor?,
    private val legacyMac: String?,
) {
    @JsName("fromLegacyMac")
    constructor(mac: String) : this(coseMac0 = null, legacyMac = mac)

    @JsName("fromCoseMac0Value")
    constructor(coseMac0: CoseMac0Cbor) : this(coseMac0 = coseMac0, legacyMac = null)

    /** Legacy text representation retained for source and wire compatibility. */
    fun toCborItem(): CborString =
        CborString(
            legacyMac
                ?: error("COSE_Mac0 must be encoded with a CoseMac0CborCodec"),
        )

    fun isCoseMac0(): Boolean = coseMac0 != null

    override fun equals(other: Any?): Boolean =
        other is DeviceMac && coseMac0 == other.coseMac0 && legacyMac == other.legacyMac

    override fun hashCode(): Int = 31 * (coseMac0?.hashCode() ?: 0) + (legacyMac?.hashCode() ?: 0)

    override fun toString(): String = coseMac0?.toString() ?: legacyMac.orEmpty()

    companion object {
        @JvmStatic
        fun fromCborItem(structure: CborString): DeviceMac = DeviceMac(structure.value)

        @JvmStatic
        fun fromCoseMac0(value: CoseMac0Cbor): DeviceMac = DeviceMac(value)
    }
}

@JsExportCompat
@OptIn(ExperimentalObjCName::class)
@ObjCName("DeviceAuth", exact = true)
data class DeviceAuth(
    val deviceSignature: COSE_Sign1<DeviceAuthentication>? = null,
    /**
     * Legacy representation of the device MAC authentication value.
     *
     * The common verifier does not currently have the session-specific EMacKey
     * needed to validate COSE_Mac0.  Keep the field for wire compatibility, but
     * never treat its presence as authenticated data.
     */
    val deviceMac: DeviceMac? = null,
    val original: ByteArray?,
) {
    init {
        assertValidState()
    }

    fun getAuthType(): DeviceAuthType {
        assertValidState()
        return if (deviceSignature != null) {
            DeviceAuthType.SIGNATURE
        } else {
            DeviceAuthType.MAC
        }
    }

    private fun assertValidState() {
        check(this.deviceSignature !== null || this.deviceMac !== null) {
            "Either a device signature or MAC should be present"
        }
        check(this.deviceMac == null || this.deviceSignature == null) {
            "Cannot have both a device signature and MAC at the same time"
        }
        // Presence is preserved for legacy decode/round-trip compatibility.  A verifier must
        // still validate the MAC with the session-specific EMacKey before accepting it; the
        // validation layer, rather than this transport model, owns that policy decision.
    }

    override fun toString(): String = "DeviceAuth(deviceSignature=$deviceSignature, deviceMac=$deviceMac, original=${stringify(original)})"

    companion object {
        @JsStatic
        @JvmStatic
        val DEVICE_SIGNATURE = StringLabel("deviceSignature")

        @JsStatic
        @JvmStatic
        val DEVICE_MAC = StringLabel("deviceMac")
    }
}

@JsExportCompat
@OptIn(ExperimentalObjCName::class)
@ObjCName("DeviceAuthentication", exact = true)
data class DeviceAuthentication(
    val sessionTranscript: SessionTranscript,
    val docType: DocType,
    val deviceNamespaces: DeviceNameSpaces,
    val original: ByteArray?,
) {
    companion object {
        /**
         * Build a DeviceAuthentication for OID4VP per §B.2.6.
         *
         * @param jwkThumbprint Raw 32-byte SHA-256 thumbprint (RFC 7638) of the verifier's
         *   encryption-key JWK. Required for `direct_post.jwt` / `dc_api.jwt`; null for plain
         *   modes.
         */
        @JsStatic
        @JvmStatic
        fun fromOid4vp(
            clientId: String,
            nonce: String,
            jwkThumbprint: ByteArray?,
            responseUri: String,
            docType: DocType,
            deviceNamespaces: DeviceNameSpaces,
        ): DeviceAuthentication {
            val sessionTranscript =
                SessionTranscript.fromOid4vpClientIdAndResponseUri(
                    clientId = clientId,
                    nonce = nonce,
                    jwkThumbprint = jwkThumbprint,
                    responseUri = responseUri,
                )
            return DeviceAuthentication(
                sessionTranscript = sessionTranscript,
                docType = docType,
                deviceNamespaces = deviceNamespaces,
                original = null,
            )
        }

        /** Build DeviceAuthentication from mode-specific, validated OID4VP request context. */
        @JsStatic
        @JvmStatic
        // JavaScript has no overloads: this one would clash with fromOid4vp(clientId, ...) above.
        @JsName("fromOid4vpContext")
        fun fromOid4vp(
            context: Oid4vpDeviceAuthenticationContext,
            docType: DocType,
            deviceNamespaces: DeviceNameSpaces,
        ): DeviceAuthentication =
            DeviceAuthentication(
                sessionTranscript = context.toSessionTranscript(),
                docType = docType,
                deviceNamespaces = deviceNamespaces,
                original = null,
            )

        /**
         * Build DeviceAuthentication for ISO/IEC TS 18013-7 Annex B.
         *
         * This must not use [fromOid4vp], whose handover is the OpenID4VP 1.0
         * final/DCQL profile. Annex B has its own three-element handover and
         * binds both URI hashes to the per-presentation mdoc-generated nonce.
         */
        @JsStatic
        @JvmStatic
        fun fromIso18013Oid4vp(
            clientId: String,
            responseUri: String,
            mdocGeneratedNonce: String,
            nonce: String,
            docType: DocType,
            deviceNamespaces: DeviceNameSpaces,
        ): DeviceAuthentication {
            val sessionTranscript =
                SessionTranscript(
                    handover =
                        Iso18013Oid4vpHandover
                            .fromInputs(
                                clientId = clientId,
                                responseUri = responseUri,
                                mdocGeneratedNonce = mdocGeneratedNonce,
                                nonce = nonce,
                            ) as com.sphereon.mdoc.transfer.reader.Handover<*, com.sphereon.cbor.CborItem<*>>,
                    original = null,
                )
            return DeviceAuthentication(
                sessionTranscript = sessionTranscript,
                docType = docType,
                deviceNamespaces = deviceNamespaces,
                original = null,
            )
        }
    }
}
