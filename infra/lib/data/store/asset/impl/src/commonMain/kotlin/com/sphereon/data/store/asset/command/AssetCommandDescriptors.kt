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

package com.sphereon.data.store.asset.command

import com.sphereon.core.api.service.ServiceCommand
import com.sphereon.di.session.SessionScope
import dev.zacsweers.metro.ContributesTo
import dev.zacsweers.metro.IntoMap
import dev.zacsweers.metro.Provides
import dev.zacsweers.metro.StringKey

/**
 * DI descriptor registration for the tenant asset commands.
 *
 * Uses Metro @IntoMap multibinding to register commands by their COMMAND_ID.
 */
@ContributesTo(SessionScope::class)
interface AssetCommandDescriptors {
    @Provides
    @IntoMap
    @StringKey(GetTenantAssetContentServiceCommand.COMMAND_ID)
    fun getTenantAssetContent(command: GetTenantAssetContentServiceCommand): ServiceCommand<*, *, *> = command
}
