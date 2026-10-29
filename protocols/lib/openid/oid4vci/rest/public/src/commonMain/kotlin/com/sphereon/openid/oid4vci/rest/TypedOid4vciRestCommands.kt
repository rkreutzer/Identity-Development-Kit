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

package com.sphereon.openid.oid4vci.rest

import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.http.describe.HttpEndpointDescriptor
import com.sphereon.core.api.service.ActionType
import com.sphereon.core.api.service.PublicApiCommand
import com.sphereon.core.api.service.ServiceCommand
import com.sphereon.core.compat.JsExportCompat
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.experimental.ExperimentalObjCName
import kotlin.native.ObjCName

/**
 * Service command for creating credential offer sessions.
 *
 * POST /api/oid4vci/v1/backend/credential/offers
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("CreateCredentialOfferServiceCommand", exact = true)
interface CreateCredentialOfferServiceCommand :
    ServiceCommand<CreateCredentialOfferInput, CreateCredentialOfferOutput, IdkError>,
    PublicApiCommand {
    companion object {
        const val COMMAND_ID = "oid4vci.rest.create"
    }

    override val commandId: String get() = COMMAND_ID
    override val actionType: ActionType get() = ActionType.CREATE
    override val httpEndpoint: HttpEndpointDescriptor get() = CreateCredentialOfferEndpointCommand.ENDPOINT
}

/**
 * Service command for getting credential offer status.
 *
 * GET /api/oid4vci/v1/backend/credential/offers/{correlation_id}
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("GetCredentialOfferStatusServiceCommand", exact = true)
interface GetCredentialOfferStatusServiceCommand :
    ServiceCommand<GetCredentialOfferStatusInput, GetCredentialOfferStatusOutput, IdkError>,
    PublicApiCommand {
    companion object {
        const val COMMAND_ID = "oid4vci.rest.status"
    }

    override val commandId: String get() = COMMAND_ID
    override val actionType: ActionType get() = ActionType.READ
    override val httpEndpoint: HttpEndpointDescriptor get() = GetCredentialOfferStatusEndpointCommand.ENDPOINT
}

/**
 * Service command for deleting credential offer sessions.
 *
 * DELETE /api/oid4vci/v1/backend/credential/offers/{correlation_id}
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("DeleteCredentialOfferServiceCommand", exact = true)
interface DeleteCredentialOfferServiceCommand :
    ServiceCommand<GetCredentialOfferStatusInput, DeleteCredentialOfferOutput, IdkError>,
    PublicApiCommand {
    companion object {
        const val COMMAND_ID = "oid4vci.rest.delete"
    }

    override val commandId: String get() = COMMAND_ID
    override val actionType: ActionType get() = ActionType.DELETE
    override val httpEndpoint: HttpEndpointDescriptor get() = DeleteCredentialOfferEndpointCommand.ENDPOINT
}

/**
 * Input for status and delete commands.
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("GetCredentialOfferStatusInput", exact = true)
@JsExportCompat
@Serializable
data class GetCredentialOfferStatusInput(
    @SerialName("correlation_id")
    val correlationId: String,
    /**
     * Issuer instance the session must belong to. A session of another instance is answered as not found. Omitted by a
     * caller that is not scoped to an instance.
     */
    @SerialName("instance_id")
    val instanceId: String? = null,
)

/**
 * Output for the delete credential offer command.
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("DeleteCredentialOfferOutput", exact = true)
@JsExportCompat
@Serializable
data class DeleteCredentialOfferOutput(
    @SerialName("correlation_id")
    val correlationId: String,
    val deleted: Boolean = true,
)
