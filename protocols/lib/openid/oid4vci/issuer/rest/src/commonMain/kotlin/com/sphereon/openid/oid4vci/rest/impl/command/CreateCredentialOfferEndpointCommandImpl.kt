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

package com.sphereon.openid.oid4vci.rest.impl.command

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.http.GenericHttpRequest
import com.sphereon.core.api.http.GenericHttpResponse
import com.sphereon.core.api.http.command.HttpEndpointCommandAdapter
import com.sphereon.core.api.http.command.HttpEndpointCommand
import com.sphereon.di.session.SessionScope
import com.sphereon.openid.oid4vci.rest.CreateCredentialOfferEndpointCommand
import com.sphereon.openid.oid4vci.rest.CreateCredentialOfferInput
import com.sphereon.openid.oid4vci.rest.CreateCredentialOfferOutput
import com.sphereon.openid.oid4vci.rest.CreateCredentialOfferServiceCommand
import com.sphereon.openid.oid4vci.rest.Oid4vciRestPaths
import com.sphereon.openid.oid4vci.rest.withRouteParams
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding
import kotlinx.serialization.json.Json

/**
 * HTTP endpoint for creating credential offer sessions.
 *
 * POST /api/oid4vci/v1/instances/{instanceId}/backend/credential/offers, and the same route without the instance segment
 * for callers that predate it.
 */
@Inject
@SingleIn(SessionScope::class)
class CreateCredentialOfferEndpointCommandImpl(
    execution: SessionExecution,
    private val createCredentialOfferServiceCommand: CreateCredentialOfferServiceCommand,
) : HttpEndpointCommandAdapter(
        id = CreateCredentialOfferEndpointCommand.COMMAND_ID,
        execution = execution,
        endpoint = CreateCredentialOfferEndpointCommand.ENDPOINT,
    ),
    CreateCredentialOfferEndpointCommand {
    private val json =
        Json {
            ignoreUnknownKeys = true
            encodeDefaults = true
        }

    override suspend fun doExecute(
        args: GenericHttpRequest,
        applyDuring: (GenericHttpRequest) -> GenericHttpRequest,
    ): IdkResult<GenericHttpResponse, IdkError> {
        val request = applyDuring(args).withRouteParams(endpoint)

        val parsed =
            parseInput(request.body)
                ?: return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Invalid or missing request body"))
        val input = parsed.boundTo(request.pathParams[Oid4vciRestPaths.INSTANCE_ID_PARAM]).getOrElse { return Err(it) }

        val output =
            createCredentialOfferServiceCommand.execute(input).getOrElse { error ->
                return Err(error)
            }

        return Ok(
            GenericHttpResponse(
                statusCode = 201,
                headers =
                    mapOf(
                        "Content-Type" to "application/json",
                        "Cache-Control" to "no-store",
                    ),
                body = json.encodeToString(CreateCredentialOfferOutput.serializer(), output),
            ),
        )
    }

    /** The route's instance is the instance of the offer, so a body that names another one is a conflicting request. */
    private fun CreateCredentialOfferInput.boundTo(routeInstanceId: String?): IdkResult<CreateCredentialOfferInput, IdkError> {
        if (routeInstanceId == null) return Ok(this)
        if (issuerInstanceId != null && issuerInstanceId != routeInstanceId) {
            return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "issuer_instance_id does not match the issuer instance of the request"))
        }
        return Ok(copy(issuerInstanceId = routeInstanceId))
    }

    private fun parseInput(body: String?): CreateCredentialOfferInput? {
        if (body.isNullOrBlank()) return null
        return try {
            json.decodeFromString(CreateCredentialOfferInput.serializer(), body)
        } catch (_: Exception) {
            null
        }
    }
}
