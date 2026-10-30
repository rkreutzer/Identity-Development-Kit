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

import com.sphereon.core.api.service.ServiceCommand
import com.sphereon.di.session.SessionScope
import com.sphereon.openid.oid4vci.rest.CreateCredentialOfferServiceCommand
import com.sphereon.openid.oid4vci.rest.DeleteCredentialOfferServiceCommand
import com.sphereon.openid.oid4vci.rest.GetCredentialOfferStatusServiceCommand
import dev.zacsweers.metro.ContributesTo
import dev.zacsweers.metro.IntoMap
import dev.zacsweers.metro.Provides
import dev.zacsweers.metro.StringKey

/**
 * Registers the typed credential offer commands in the session command registry, so a caller that routes them over
 * a transport resolves each by its command id with the typed input. The HTTP endpoint commands share these ids and
 * take the raw request instead.
 */
@ContributesTo(SessionScope::class)
interface Oid4vciRestCommandDescriptors {
    @Provides @IntoMap @StringKey(CreateCredentialOfferServiceCommand.COMMAND_ID)
    fun createCredentialOffer(impl: CreateCredentialOfferServiceCommand): ServiceCommand<*, *, *> = impl

    @Provides @IntoMap @StringKey(GetCredentialOfferStatusServiceCommand.COMMAND_ID)
    fun getCredentialOfferStatus(impl: GetCredentialOfferStatusServiceCommand): ServiceCommand<*, *, *> = impl

    @Provides @IntoMap @StringKey(DeleteCredentialOfferServiceCommand.COMMAND_ID)
    fun deleteCredentialOffer(impl: DeleteCredentialOfferServiceCommand): ServiceCommand<*, *, *> = impl
}
