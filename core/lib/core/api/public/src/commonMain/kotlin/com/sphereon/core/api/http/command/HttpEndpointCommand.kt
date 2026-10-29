/*
 * (c) 2026 Sphereon International B.V.
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

package com.sphereon.core.api.http.command

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.context.ContextConfig
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.http.GenericHttpRequest
import com.sphereon.core.api.http.GenericHttpResponse
import com.sphereon.core.api.http.describe.HttpEndpointDescriptor
import com.sphereon.core.api.session.Command
import com.sphereon.core.api.session.ExecutionScopedCommandAdapter
import com.sphereon.core.api.session.ICommandExecutionExtension
import com.sphereon.core.api.session.ICommandInitExtension
import com.sphereon.core.compat.JsExportCompat

/**
 * Command interface for HTTP endpoint handlers.
 *
 * Each endpoint in an adapter can be modeled as a command, enabling:
 * - Lifecycle integration (via `Scoped`)
 * - Enablement/feature gating (via `isEnabled`)
 * - "During" mutation hooks/extensions
 * - Consistent execution patterns across the codebase
 *
 * The `endpoint` descriptor provides metadata for routing and introspection,
 * while `execute()` handles the actual request processing.
 *
 * Example:
 * ```kotlin
 * class GetKeyEndpointCommand(
 *     execution: SessionExecution,
 *     private val kmsService: KmsRestService
 * ) : HttpEndpointCommandAdapter(
 *     id = "kms.keys.get",
 *     execution = execution,
 *     endpoint = HttpEndpointDescriptor(
 *         method = HttpMethod.GET,
 *         pathPattern = "/keys/{aliasOrKid}",
 *         produces = setOf(MediaType.ApplicationJson)
 *     )
 * ) {
 *     override suspend fun doExecute(
 *         args: GenericHttpRequest,
 *         applyDuring: (GenericHttpRequest) -> GenericHttpRequest
 *     ): IdkResult<GenericHttpResponse, IdkError> {
 *         val req = applyDuring(args)
 *         // ... handle request
 *     }
 * }
 * ```
 */
@JsExportCompat
interface HttpEndpointCommand : Command<GenericHttpRequest, GenericHttpResponse, IdkError> {
    /**
     * The endpoint descriptor for this command.
     *
     * Provides metadata used for:
     * - Routing (method + pathPattern matching)
     * - OpenAPI generation (consumes/produces/operationId/tags)
     * - Introspection and discovery
     */
    val endpoint: HttpEndpointDescriptor

    /**
     * Single-segment resource parameters that explicitly accept opaque percent-encoded identifiers.
     * These are decoded once after matching; literals and other parameters retain strict path checks.
     */
    val encodedPathParameters: Set<String> get() = emptySet()

    /**
     * Determines if this command can handle the given request.
     *
     * Default implementation matches the request against the endpoint descriptor.
     * Subclasses can override for more complex matching logic (e.g., content-type negotiation).
     */
    override suspend fun supports(args: Any): Boolean =
        if (args is GenericHttpRequest) {
            // Iterate every pattern this descriptor exposes — multi-pattern descriptors
            // (e.g. metadata served at both spec-suffix and legacy-prefix URLs) MUST
            // match a request hitting any of them.
            endpoint.pathPatterns.any { args.matches(endpoint.method.name, it) }
        } else {
            false
        }
}

/**
 * Base adapter for [HttpEndpointCommand] implementations.
 *
 * Extends [ExecutionScopedCommandAdapter] to integrate with the IDK command infrastructure,
 * providing:
 * - Automatic session registration via `onEnterScope`
 * - Execution extensions (before/during/after hooks)
 * - Init extensions
 * - Plugin integration
 *
 * Subclasses must override [doExecute] to implement the actual endpoint logic.
 *
 * @param id Unique identifier for this endpoint command (e.g., "kms.keys.get")
 * @param execution The session execution context
 * @param endpoint The HTTP endpoint descriptor
 * @param isEnabled Whether this command is enabled (default: true)
 * @param initExtensions Initialization lifecycle hooks
 * @param executionExtensions Execution lifecycle hooks (before/during/after)
 */
abstract class HttpEndpointCommandAdapter(
    id: String,
    execution: SessionExecution,
    override val endpoint: HttpEndpointDescriptor,
    isEnabled: Boolean = true,
    initExtensions: Array<ICommandInitExtension<GenericHttpRequest, GenericHttpResponse, IdkError>> = emptyArray(),
    executionExtensions: Array<ICommandExecutionExtension<GenericHttpRequest, GenericHttpResponse, IdkError>> = emptyArray(),
) : ExecutionScopedCommandAdapter<GenericHttpRequest, GenericHttpResponse, IdkError>(
        id = id,
        isEnabled = isEnabled,
        initExtensions = initExtensions,
        executionExtensions = executionExtensions,
        execution = execution,
    ),
    HttpEndpointCommand {
    /**
     * Access to the session configuration.
     */
    protected val config: ContextConfig get() = conf

    /**
     * Simplified constructor for common use cases.
     */
    constructor(
        id: String,
        execution: SessionExecution,
        endpoint: HttpEndpointDescriptor,
    ) : this(
        id = id,
        execution = execution,
        endpoint = endpoint,
        isEnabled = true,
        initExtensions = emptyArray(),
        executionExtensions = emptyArray(),
    )
}
