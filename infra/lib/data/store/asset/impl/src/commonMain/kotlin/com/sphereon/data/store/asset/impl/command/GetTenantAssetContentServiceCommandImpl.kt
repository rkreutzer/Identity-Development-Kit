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

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.service.TypedServiceCommandAdapter
import com.sphereon.core.api.validation.validate
import com.sphereon.data.store.asset.TenantAssetService
import com.sphereon.data.store.asset.command.GetTenantAssetContentArgs
import com.sphereon.data.store.asset.command.GetTenantAssetContentServiceCommand
import com.sphereon.data.store.asset.error.AssetError
import com.sphereon.data.store.asset.model.ResolvedAsset
import com.sphereon.data.store.asset.validation.validateGetTenantAssetContentArgs
import com.sphereon.di.context.IdentityConstants
import com.sphereon.di.session.SessionScope
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding

/**
 * Reads one asset of the session's tenant from the tenant asset library.
 *
 * The request carries no tenant: it is the one the session resolves to, from the host, the path or an optional token,
 * so a caller cannot name another tenant's asset. The principal is not consulted, because a portal page can be public
 * and its visitor anonymous. A session that resolves no tenant is refused before anything is read.
 */
@Inject
@SingleIn(SessionScope::class)
@ContributesBinding(SessionScope::class, binding = binding<GetTenantAssetContentServiceCommand>())
class GetTenantAssetContentServiceCommandImpl(
    execution: SessionExecution,
    private val assets: TenantAssetService,
) : TypedServiceCommandAdapter<GetTenantAssetContentArgs, ResolvedAsset, IdkError>(
        commandId = GetTenantAssetContentServiceCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<GetTenantAssetContentArgs>(),
        outputTypeToken = typeToken<ResolvedAsset>(),
    ),
    GetTenantAssetContentServiceCommand {
    override val commandId: String get() = GetTenantAssetContentServiceCommand.COMMAND_ID

    override suspend fun doExecute(
        args: GetTenantAssetContentArgs,
        applyDuring: (GetTenantAssetContentArgs) -> GetTenantAssetContentArgs,
    ): IdkResult<ResolvedAsset, IdkError> {
        if (!execution.hasResolvedTenant()) {
            return Err(IdkError.UNAUTHORIZED_ERROR(message = "Missing tenant identification"))
        }
        val applied = applyDuring(args)
        validate(validateGetTenantAssetContentArgs, applied) { IdkError.fromDTO(AssetError.ValidationError(it)) }
            .getOrElse { return Err(it) }
        return assets.getAssetContent(execution.tenantId, applied.namespace, applied.hash)
    }
}

/**
 * Whether the session names a tenant that is not the anonymous sentinel.
 *
 * Only the tenant is required. It is what the asset library scopes every read by, and an anonymous principal can still
 * belong to a resolved tenant.
 */
private fun SessionExecution.hasResolvedTenant(): Boolean = tenantId.isNotBlank() && tenantId != IdentityConstants.ANONYMOUS_TENANT_ID
