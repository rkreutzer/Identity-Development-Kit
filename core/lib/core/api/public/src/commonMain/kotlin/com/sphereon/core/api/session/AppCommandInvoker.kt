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

package com.sphereon.core.api.session

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.context.asCoreApiContextGraph
import com.sphereon.core.api.error.IdkErrorType
import com.sphereon.core.api.service.ServiceCommand
import com.sphereon.di.context.PrincipalInput
import com.sphereon.di.context.SecuredTenantContextDetails
import com.sphereon.di.context.TenantInput
import com.sphereon.di.context.UserContextManager
import dev.zacsweers.metro.AppScope
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding
import kotlin.experimental.ExperimentalObjCName
import kotlin.native.ObjCName
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/**
 * App-scoped command executor that supports cross-tenant execution.
 *
 * Extends [CommandInvoker] with an overload that accepts explicit tenant/principal context.
 * The base [CommandInvoker] methods delegate via a background service context.
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("AppCommandInvoker", exact = true)
interface AppCommandInvoker : CommandInvoker {
    /**
     * Execute a command with explicit tenant/principal context.
     *
     * Creates or gets the user context for the given tenant/principal,
     * then opens a fresh session-scoped executor for this execution. Each
     * call gets its own [com.sphereon.core.api.context.SessionExecution],
     * isolating per-execution state (notably `correlationId`) between
     * concurrent dispatch-side callers that share a (tenant, principal).
     *
     * @param correlationId Cross-cutting trace key for this execution. Pass
     *   `null` to fall back to the freshly-generated session id. Supply
     *   explicitly when replaying a durable row, dispatching a scheduled
     *   job, or continuing a correlation chain from a parent execution.
     */
    suspend fun <TInput : Any, TOutput : Any, TError : IdkErrorType> execute(
        tenantInput: TenantInput,
        principalInput: PrincipalInput,
        command: ServiceCommand<TInput, TOutput, TError>,
        input: TInput,
        correlationId: String? = null,
    ): IdkResult<TOutput, TError>
}

/**
 * App command execution for a server-created, already authenticated bearer.
 * Implementations must bind [secureDetails] to the per-execution session, never
 * to the cached tenant/principal user context.
 */
interface SecuredAppCommandInvoker {
    suspend fun <TInput : Any, TOutput : Any, TError : IdkErrorType> executeWithSecureDetails(
        tenantInput: TenantInput,
        principalInput: PrincipalInput,
        command: ServiceCommand<TInput, TOutput, TError>,
        input: TInput,
        secureDetails: SecuredTenantContextDetails,
        correlationId: String? = null,
    ): IdkResult<TOutput, TError>
}

@Inject
@SingleIn(AppScope::class)
@ContributesBinding(AppScope::class, binding = binding<AppCommandInvoker>())
@ContributesBinding(AppScope::class, binding = binding<SecuredAppCommandInvoker>())
@OptIn(ExperimentalObjCName::class, ExperimentalUuidApi::class)
@ObjCName("AppCommandInvokerImpl", exact = true)
class AppCommandInvokerImpl(
    val userContextManager: UserContextManager,
) : AppCommandInvoker, SecuredAppCommandInvoker {
    private fun backgroundExecutor(): CommandInvoker = userContextManager.getBackgroundService().asCoreApiContextGraph().commandInvoker

    override fun resolve(commandId: String): ServiceCommand<*, *, *>? = backgroundExecutor().resolve(commandId)

    override suspend fun <TInput : Any, TOutput : Any, TError : IdkErrorType> execute(
        command: ServiceCommand<TInput, TOutput, TError>,
        input: TInput,
    ): IdkResult<TOutput, TError> = backgroundExecutor().execute(command, input)

    override fun has(commandId: String): Boolean = backgroundExecutor().has(commandId)

    override fun listCommandIds(): List<String> = backgroundExecutor().listCommandIds()

    @Suppress("UNCHECKED_CAST")
    override suspend fun <TInput : Any, TOutput : Any, TError : IdkErrorType> execute(
        tenantInput: TenantInput,
        principalInput: PrincipalInput,
        command: ServiceCommand<TInput, TOutput, TError>,
        input: TInput,
        correlationId: String?,
    ): IdkResult<TOutput, TError> = executeInternal(
        tenantInput = tenantInput,
        principalInput = principalInput,
        command = command,
        input = input,
        secureDetails = null,
        correlationId = correlationId,
    )

    override suspend fun <TInput : Any, TOutput : Any, TError : IdkErrorType> executeWithSecureDetails(
        tenantInput: TenantInput,
        principalInput: PrincipalInput,
        command: ServiceCommand<TInput, TOutput, TError>,
        input: TInput,
        secureDetails: SecuredTenantContextDetails,
        correlationId: String?,
    ): IdkResult<TOutput, TError> = executeInternal(
        tenantInput = tenantInput,
        principalInput = principalInput,
        command = command,
        input = input,
        secureDetails = secureDetails,
        correlationId = correlationId,
    )

    @Suppress("UNCHECKED_CAST")
    private suspend fun <TInput : Any, TOutput : Any, TError : IdkErrorType> executeInternal(
        tenantInput: TenantInput,
        principalInput: PrincipalInput,
        command: ServiceCommand<TInput, TOutput, TError>,
        input: TInput,
        secureDetails: SecuredTenantContextDetails?,
        correlationId: String?,
    ): IdkResult<TOutput, TError> {
        val activeContext = userContextManager.createOrGetFromInputs(tenantInput, principalInput)
        val sessionId = Uuid.random().toString()
        val resolvedCorrelationId = correlationId ?: sessionId
        val sessionContextManager = activeContext.asCoreApiContextGraph().sessionContextManager
        val sessionInstance =
            sessionContextManager
                .createOrGetFromId(
                    sessionId = sessionId,
                    correlationId = resolvedCorrelationId,
                    makeActive = false,
                    secureDetails = secureDetails,
                    principalType = activeContext.context.principalType,
                )
        val executor = (sessionInstance.graph as CommandInvokerGraph).commandInvoker
        return try {
            // Re-resolve the command from the freshly opened session's executor so
            // any SessionScope-bound state (e.g. SessionExecution captured in the
            // constructor of a @SingleIn(SessionScope::class) ServiceCommand) refers
            // to THIS session — not the background session the caller used to
            // resolve the passed-in instance. Falls back to the supplied instance
            // when the new session has no binding for this id (e.g. ad-hoc commands).
            val effective = executor.resolve(command.commandId) as? ServiceCommand<TInput, TOutput, TError> ?: command
            executor.execute(effective, input)
        } finally {
            sessionContextManager.destroyById(sessionId)
        }
    }
}
