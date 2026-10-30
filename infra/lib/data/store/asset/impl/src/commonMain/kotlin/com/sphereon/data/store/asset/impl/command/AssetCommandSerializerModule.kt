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

import com.sphereon.core.api.codec.CommandSerializerEntry
import com.sphereon.data.store.asset.command.GetTenantAssetContentArgs
import com.sphereon.data.store.asset.model.ResolvedAsset
import dev.zacsweers.metro.AppScope
import dev.zacsweers.metro.ContributesTo
import dev.zacsweers.metro.IntoSet
import dev.zacsweers.metro.Provides

/**
 * Compile-time serializer registry entries for every payload type in [com.sphereon.data.store.asset.command.AssetCommandDescriptors].
 *
 * The JSON, CBOR and Protobuf codecs resolve serializers from this multibinding and nowhere else, and have no
 * reflective fallback because kotlin-reflect is excluded from the runtime classpath for native-image support. A payload
 * type that is `@Serializable` but not registered here cannot cross the binary transport: the command authenticates,
 * routes and reaches its handler, then fails decoding its own request with `No registered serializer for <Type>`.
 * The asset commands are hand-written adapters, so nothing generates these entries.
 *
 * Adding a command to [com.sphereon.data.store.asset.command.AssetCommandDescriptors] means adding its input and output types here.
 * `AssetCommandSerializerModuleTest` fails when a payload type is missing.
 */
@ContributesTo(AppScope::class)
interface AssetCommandSerializerModule {
    /** Input of `assets.content.get`. */
    @Provides
    @IntoSet
    fun provideGetTenantAssetContentArgsSerializerEntry(): CommandSerializerEntry =
        CommandSerializerEntry(GetTenantAssetContentArgs::class, GetTenantAssetContentArgs.serializer())

    /** Output of `assets.content.get`. */
    @Provides
    @IntoSet
    fun provideResolvedAssetSerializerEntry(): CommandSerializerEntry =
        CommandSerializerEntry(ResolvedAsset::class, ResolvedAsset.serializer())
}
