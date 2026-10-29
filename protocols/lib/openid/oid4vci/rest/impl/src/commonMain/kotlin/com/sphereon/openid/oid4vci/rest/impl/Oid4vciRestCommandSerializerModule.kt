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

package com.sphereon.openid.oid4vci.rest.impl

import com.sphereon.core.api.codec.CommandSerializerEntry
import com.sphereon.openid.oid4vci.rest.CreateCredentialOfferInput
import com.sphereon.openid.oid4vci.rest.CreateCredentialOfferOutput
import com.sphereon.openid.oid4vci.rest.DeleteCredentialOfferOutput
import com.sphereon.openid.oid4vci.rest.GetCredentialOfferStatusInput
import com.sphereon.openid.oid4vci.rest.GetCredentialOfferStatusOutput
import dev.zacsweers.metro.AppScope
import dev.zacsweers.metro.ContributesTo
import dev.zacsweers.metro.IntoSet
import dev.zacsweers.metro.Provides

/**
 * Compile-time serializers for the inputs and outputs of the typed credential offer commands. The binary transport
 * decodes a routed command's payload through its application-scoped codec, which cannot use reflection in a native
 * image.
 */
@ContributesTo(AppScope::class)
interface Oid4vciRestCommandSerializerModule {
    @Provides @IntoSet
    fun createCredentialOfferInput(): CommandSerializerEntry =
        CommandSerializerEntry(CreateCredentialOfferInput::class, CreateCredentialOfferInput.serializer())

    @Provides @IntoSet
    fun createCredentialOfferOutput(): CommandSerializerEntry =
        CommandSerializerEntry(CreateCredentialOfferOutput::class, CreateCredentialOfferOutput.serializer())

    @Provides @IntoSet
    fun getCredentialOfferStatusInput(): CommandSerializerEntry =
        CommandSerializerEntry(GetCredentialOfferStatusInput::class, GetCredentialOfferStatusInput.serializer())

    @Provides @IntoSet
    fun getCredentialOfferStatusOutput(): CommandSerializerEntry =
        CommandSerializerEntry(GetCredentialOfferStatusOutput::class, GetCredentialOfferStatusOutput.serializer())

    @Provides @IntoSet
    fun deleteCredentialOfferOutput(): CommandSerializerEntry =
        CommandSerializerEntry(DeleteCredentialOfferOutput::class, DeleteCredentialOfferOutput.serializer())
}
