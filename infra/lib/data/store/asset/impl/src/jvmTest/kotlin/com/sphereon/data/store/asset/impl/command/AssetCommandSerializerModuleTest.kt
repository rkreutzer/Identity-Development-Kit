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

package com.sphereon.data.store.asset.impl.command

import com.sphereon.core.api.binary.StreamingBody
import com.sphereon.core.api.binary.TypeToken
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.codec.CommandSerializerEntry
import com.sphereon.core.api.codec.JsonStreamingCodec
import com.sphereon.data.store.asset.command.GetTenantAssetContentArgs
import com.sphereon.data.store.asset.model.AssetInfo
import com.sphereon.data.store.asset.model.AssetNamespace
import com.sphereon.data.store.asset.model.ResolvedAsset
import kotlin.reflect.KClass
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Pins the compile-time serializer coverage of the tenant asset commands.
 *
 * The codecs resolve serializers from the [CommandSerializerEntry] multibinding and have no reflective fallback, so a
 * payload type that is missing here cannot cross the binary transport: the command reaches its handler and then fails
 * decoding its own request.
 */
class AssetCommandSerializerModuleTest {
    private val sha256OfAbc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

    private val entries: Set<CommandSerializerEntry> =
        run {
            val module = object : AssetCommandSerializerModule {}
            module.javaClass.methods
                .filter { it.parameterCount == 0 && CommandSerializerEntry::class.java.isAssignableFrom(it.returnType) }
                .map { it.invoke(module) as CommandSerializerEntry }
                .toSet()
        }

    private fun resolves(typeToken: TypeToken<*>): Boolean {
        val byType = entries.mapNotNull { entry -> entry.kType?.let { it to entry.serializer } }.toMap()
        val byClass = entries.filter { it.kType == null }.associate { it.kClass to it.serializer }
        if (byType.containsKey(typeToken.kType)) return true
        val kClass = typeToken.kType.classifier as? KClass<*> ?: return false
        return byClass.containsKey(kClass)
    }

    @Test
    fun shouldRegisterEveryPayloadTypeOfTheTenantAssetContentCommand() {
        val payloadTypes =
            listOf(
                "assets.content.get in" to typeToken<GetTenantAssetContentArgs>(),
                "assets.content.get out" to typeToken<ResolvedAsset>(),
            )

        val missing = payloadTypes.filterNot { (_, token) -> resolves(token) }.map { (what, token) -> "$what (${token.qualifiedName})" }

        assertTrue(missing.isEmpty(), "these asset command payload types cannot cross the binary transport: $missing")
    }

    @Test
    fun shouldDecodeTheRequestTheCallerSendsThroughTheJsonCodec() {
        val codec = JsonStreamingCodec(serializerEntries = entries)
        val body = StreamingBody.Text("""{"namespace":"brand","hash":"$sha256OfAbc"}""")

        val decoded = codec.decode(body, typeToken<GetTenantAssetContentArgs>())

        assertTrue(decoded.isOk, "assets.content.get input must decode")
        assertEquals(GetTenantAssetContentArgs(AssetNamespace.BRAND, sha256OfAbc), decoded.value)
    }

    @Test
    fun shouldRoundTripTheAssetWithItsBytesAsBase64() {
        val codec = JsonStreamingCodec(serializerEntries = entries)
        val asset =
            ResolvedAsset(
                data = byteArrayOf(1, 2, 3),
                contentType = "image/png",
                info = AssetInfo("/public/assets/tenant-a/brand/$sha256OfAbc.png", "image/png", sha256OfAbc, 3L),
            )

        val encoded = codec.encode(asset)
        assertTrue(encoded.isOk, "assets.content.get output must encode")
        assertTrue(encoded.value.asTextOrNull().orEmpty().contains("\"data\":\"AQID\""), "bytes must travel as base64 text")

        val decoded = codec.decode(encoded.value, typeToken<ResolvedAsset>())
        assertTrue(decoded.isOk, "assets.content.get output must decode")
        assertEquals(asset, decoded.value)
    }
}
