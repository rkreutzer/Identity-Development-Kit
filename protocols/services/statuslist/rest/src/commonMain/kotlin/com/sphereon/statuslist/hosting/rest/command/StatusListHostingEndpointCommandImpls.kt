/*
 * © 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

package com.sphereon.statuslist.hosting.rest.command

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.http.GenericHttpRequest
import com.sphereon.core.api.http.GenericHttpResponse
import com.sphereon.core.api.http.command.HttpEndpointCommandAdapter
import com.sphereon.core.api.http.command.HttpEndpointCommand
import com.sphereon.core.api.http.command.requirePathParam
import com.sphereon.core.api.http.describe.HttpEndpointDescriptor
import com.sphereon.core.api.http.response.ResponseBuilder
import com.sphereon.core.api.http.util.RequestUtils
import com.sphereon.di.session.SessionScope
import com.sphereon.statuslist.StatusListErrors
import com.sphereon.statuslist.StatusListHostingMode
import com.sphereon.statuslist.StatusListRef
import com.sphereon.statuslist.StatusListToken
import com.sphereon.statuslist.command.GetStatusListTokenCommand
import com.sphereon.statuslist.hosting.rest.StatusListHostingApiConstants
import com.sphereon.statuslist.hosting.rest.StatusListHostingApiConstants.CommandIds
import com.sphereon.statuslist.hosting.rest.StatusListHostingConfig
import com.sphereon.statuslist.hosting.rest.http.GetStatusListTokenByCorrelationIdEndpointCommand
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.ContributesIntoMap
import dev.zacsweers.metro.StringKey
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding

private const val PARAM_CORRELATION_ID = "correlationId"

/**
 * Shared base for the hosting endpoints: resolves a [StatusListRef] from the URL, delegates to the
 * IDK [GetStatusListTokenCommand], and renders the raw signed token as the response body with the
 * token's own media type and a `Cache-Control: public, max-age=<ttl>` header. The token string is
 * emitted verbatim as UTF-8 bytes so the body is the exact URI a verifier resolves, never a JSON
 * envelope.
 *
 * Status lists are globally unique by their full hosting URL. The public GET resolves a list by the
 * full reconstructed request URL (proxy-aware scheme + host + request path) matched tenant-agnostic
 * against the stored `status_list_uri`, which is the exact URL recorded at creation time.
 */
abstract class AbstractGetStatusListTokenEndpointCommand(
    id: String,
    execution: SessionExecution,
    endpoint: HttpEndpointDescriptor,
    private val service: GetStatusListTokenCommand,
    private val hostingConfig: StatusListHostingConfig,
) : HttpEndpointCommandAdapter(
        id = id,
        execution = execution,
        endpoint = endpoint,
    ) {
    /** Build the reference from the matched request. */
    protected abstract fun resolveRef(request: GenericHttpRequest): IdkResult<StatusListRef, IdkError>

    final override suspend fun doExecute(
        args: GenericHttpRequest,
        applyDuring: (GenericHttpRequest) -> GenericHttpRequest,
    ): IdkResult<GenericHttpResponse, IdkError> {
        val request = applyDuring(args)
        val ref = resolveRef(request).getOrElse { return Err(it) }
        // Read publication mode and token from the same URL-resolved list. A tenant-scoped
        // management lookup can miss this list or select another tenant's correlation-id match.
        val token = service.execute(ref).getOrElse { return Err(it) }
        if (token.hostingMode == StatusListHostingMode.EXPORT) {
            return Err(StatusListErrors.listNotFound(ref.correlationId ?: ref.statusListUri ?: "<none>"))
        }
        return Ok(token.toRawResponse())
    }

    private fun StatusListToken.toRawResponse(): GenericHttpResponse {
        val maxAge =
            hostingConfig.cacheMaxAgeSeconds
                ?: ttlSeconds
                ?: StatusListHostingApiConstants.DEFAULT_CACHE_MAX_AGE_SECONDS
        return ResponseBuilder.bytesResponse(
            // rawBytes() serves the binary CWT (COSE_Sign1) verbatim, or the UTF-8 JWS for JWT/VC-JWT.
            data = rawBytes(),
            contentType = contentType,
            cacheControl = "public, max-age=$maxAge",
        )
    }
}

/** `GET /public/statuslists/{correlationId}` resolves the token by business correlation id. */
@Inject
@SingleIn(SessionScope::class)
@ContributesIntoMap(SessionScope::class, binding = binding<HttpEndpointCommand>())
@StringKey(GetStatusListTokenByCorrelationIdEndpointCommand.COMMAND_ID)
class GetStatusListTokenByCorrelationIdEndpointCommandImpl(
    execution: SessionExecution,
    service: GetStatusListTokenCommand,
    private val hostingConfig: StatusListHostingConfig,
) : AbstractGetStatusListTokenEndpointCommand(
        id = GetStatusListTokenByCorrelationIdEndpointCommand.COMMAND_ID,
        execution = execution,
        endpoint = GetStatusListTokenByCorrelationIdEndpointCommand.ENDPOINT,
        service = service,
        hostingConfig = hostingConfig,
    ),
    GetStatusListTokenByCorrelationIdEndpointCommand {
    override fun resolveRef(request: GenericHttpRequest): IdkResult<StatusListRef, IdkError> {
        val correlationId = request.requirePathParam(PARAM_CORRELATION_ID).getOrElse { return Err(it) }
        // Resolve by the list's full hosting URL, matched tenant-agnostic against the stored
        // status_list_uri (the exact URL recorded at creation). In a multi-tenant deployment each
        // tenant hosts its lists on its own public host, so the URL is reconstructed from the
        // (gateway-preserved) request host + the adapter base-path — `request.path` is already
        // base-path-stripped (e.g. "/{id}"), so the base-path is re-prefixed to match the stored
        // "<base-path>/{id}". A single configured external-base-url cannot represent every tenant's
        // host, so it is not used here; the correlationId is the tenant-scoped business-key fallback
        // (the GET resolves the tenant from that same host) for lists whose stored `uri` is an
        // explicit value the request URL can't reproduce.
        val fullUrl =
            RequestUtils.buildFullUrl(
                headers = request.headers,
                path = request.path,
                basePath = hostingConfig.basePath,
            )
        return Ok(StatusListRef(statusListUri = fullUrl, correlationId = correlationId))
    }
}
