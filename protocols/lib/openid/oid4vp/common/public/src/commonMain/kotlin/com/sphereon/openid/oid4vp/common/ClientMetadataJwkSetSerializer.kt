/*
 * Copyright 2026 Sphereon International B.V.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sphereon.openid.oid4vp.common

import com.sphereon.crypto.core.jose.Jwk
import com.sphereon.crypto.core.jose.JwkSet
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonObject

/** Ignores unsupported verifier keys per RFC 7517 section 5, using the existing JWK parser. */
internal object ClientMetadataJwkSetSerializer : KSerializer<JwkSet> {
    private val delegate = JwkSet.serializer()
    override val descriptor: SerialDescriptor = delegate.descriptor

    override fun serialize(encoder: Encoder, value: JwkSet) = delegate.serialize(encoder, value)

    override fun deserialize(decoder: Decoder): JwkSet {
        if (decoder !is JsonDecoder) return delegate.deserialize(decoder)
        val set = decoder.decodeJsonElement() as? JsonObject ?: throw SerializationException("JWKS must be an object")
        val keys = set["keys"] as? JsonArray ?: throw SerializationException("JWKS keys must be an array")
        val supported =
            keys.mapNotNull { value ->
                val key = value as? JsonObject ?: throw SerializationException("Each JWKS key must be an object")
                try {
                    Jwk.tryFromJsonObject(key).getOrNull()
                } catch (_: IllegalArgumentException) {
                    // Unknown key types, algorithms and curves cannot be used by this implementation.
                    null
                }
            }
        return JwkSet(supported.toTypedArray())
    }
}
