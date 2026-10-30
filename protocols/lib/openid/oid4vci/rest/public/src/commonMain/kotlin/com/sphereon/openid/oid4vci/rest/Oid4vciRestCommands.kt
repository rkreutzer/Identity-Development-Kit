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

import com.sphereon.core.api.http.GenericHttpRequest
import com.sphereon.core.api.http.command.HttpEndpointCommand
import com.sphereon.core.api.http.describe.HttpEndpointDescriptor
import com.sphereon.core.api.http.describe.HttpMethod
import com.sphereon.core.api.http.describe.MediaType
import kotlin.experimental.ExperimentalObjCName
import kotlin.native.ObjCName

/**
 * Route templates of the credential-offer backend API. The instance-scoped form is the published contract and is listed
 * first. The form without an instance stays mounted for callers that predate it and is not part of the published
 * OpenAPI, so such a caller selects the instance through the request body or the deployment's routing.
 */
object Oid4vciRestPaths {
    const val INSTANCE_ID_PARAM: String = "instanceId"
    const val CORRELATION_ID_PARAM: String = "correlation_id"

    const val OFFERS: String = "/backend/credential/offers"
    const val OFFER: String = "$OFFERS/{$CORRELATION_ID_PARAM}"

    const val INSTANCE_OFFERS: String = "/instances/{$INSTANCE_ID_PARAM}$OFFERS"
    const val INSTANCE_OFFER: String = "/instances/{$INSTANCE_ID_PARAM}$OFFER"
}

/**
 * Extracts the path parameters of whichever of the [endpoint]'s routes this request was made on. A pattern the request
 * does not match contributes nothing, so a request on the route without an instance carries no [Oid4vciRestPaths.INSTANCE_ID_PARAM].
 */
fun GenericHttpRequest.withRouteParams(endpoint: HttpEndpointDescriptor): GenericHttpRequest =
    endpoint.pathPatterns.fold(this) { request, pattern -> request.withExtractedParams(pattern) }

/**
 * HTTP endpoint command for creating credential offers.
 *
 * POST /api/oid4vci/v1/instances/{instanceId}/backend/credential/offers
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("CreateCredentialOfferEndpointCommand", exact = true)
interface CreateCredentialOfferEndpointCommand : HttpEndpointCommand {
    companion object {
        const val COMMAND_ID = "oid4vci.rest.create"

        val ENDPOINT =
            HttpEndpointDescriptor(
                method = HttpMethod.POST,
                pathPatterns = listOf(Oid4vciRestPaths.INSTANCE_OFFERS, Oid4vciRestPaths.OFFERS),
                consumes = setOf(MediaType.ApplicationJson),
                produces = setOf(MediaType.ApplicationJson),
                operationId = "createCredentialOffer",
                commandId = COMMAND_ID,
                handlerCommandId = COMMAND_ID,
                tags = setOf("oid4vci-rest", "credential-offers"),
                summary = "Create a new OID4VCI credential offer session",
            )
    }
}

/**
 * HTTP endpoint command for getting credential offer status.
 *
 * GET /api/oid4vci/v1/instances/{instanceId}/backend/credential/offers/{correlation_id}
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("GetCredentialOfferStatusEndpointCommand", exact = true)
interface GetCredentialOfferStatusEndpointCommand : HttpEndpointCommand {
    companion object {
        const val COMMAND_ID = "oid4vci.rest.status"

        val ENDPOINT =
            HttpEndpointDescriptor(
                method = HttpMethod.GET,
                pathPatterns = listOf(Oid4vciRestPaths.INSTANCE_OFFER, Oid4vciRestPaths.OFFER),
                produces = setOf(MediaType.ApplicationJson),
                operationId = "getCredentialOfferStatus",
                commandId = COMMAND_ID,
                handlerCommandId = COMMAND_ID,
                tags = setOf("oid4vci-rest", "credential-offers"),
                summary = "Get the status of an OID4VCI credential offer session",
            )
    }
}

/**
 * HTTP endpoint command for deleting credential offers.
 *
 * DELETE /api/oid4vci/v1/instances/{instanceId}/backend/credential/offers/{correlation_id}
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("DeleteCredentialOfferEndpointCommand", exact = true)
interface DeleteCredentialOfferEndpointCommand : HttpEndpointCommand {
    companion object {
        const val COMMAND_ID = "oid4vci.rest.delete"

        val ENDPOINT =
            HttpEndpointDescriptor(
                method = HttpMethod.DELETE,
                pathPatterns = listOf(Oid4vciRestPaths.INSTANCE_OFFER, Oid4vciRestPaths.OFFER),
                produces = setOf(MediaType.ApplicationJson),
                operationId = "deleteCredentialOffer",
                commandId = COMMAND_ID,
                handlerCommandId = COMMAND_ID,
                tags = setOf("oid4vci-rest", "credential-offers"),
                summary = "Delete an OID4VCI credential offer session",
            )
    }
}
