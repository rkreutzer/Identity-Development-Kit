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

import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.service.ActionType
import com.sphereon.core.api.service.ServiceCommand
import com.sphereon.core.compat.JsExportCompat
import com.sphereon.data.store.asset.model.AssetNamespace
import com.sphereon.data.store.asset.model.ResolvedAsset
import kotlinx.serialization.Serializable

/**
 * Selects one stored asset of the session's tenant. The tenant is not part of the request: it is the tenant the session
 * resolves to.
 *
 * @property namespace the library namespace the asset was uploaded to
 * @property hash the lowercase hexadecimal content digest of the asset bytes, as the asset library computed it on upload
 */
@JsExportCompat
@Serializable
data class GetTenantAssetContentArgs(
    val namespace: AssetNamespace,
    val hash: String,
)

/**
 * Reads content-addressed asset bytes in the session's tenant. The caller may be anonymous, because only the tenant has
 * to be resolved.
 *
 * The result is the asset, or one of three errors: an unauthorized error when the session resolves no tenant, a
 * validation error when [GetTenantAssetContentArgs.hash] is not a lowercase hexadecimal content digest, and the asset
 * library's not-found error when the tenant holds no such asset.
 */
@JsExportCompat
interface GetTenantAssetContentServiceCommand : ServiceCommand<GetTenantAssetContentArgs, ResolvedAsset, IdkError> {
    override val commandId: String get() = COMMAND_ID
    override val actionType: ActionType get() = ActionType.READ

    companion object {
        const val COMMAND_ID: String = "assets.content.get"
    }
}
