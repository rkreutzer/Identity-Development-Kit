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
 *
 */

package com.sphereon.ktor.server.inject.interceptor

import com.sphereon.core.api.app.CoreApiAppExtensionGraph
import com.sphereon.core.api.log.LogService
import com.sphereon.core.defaults.context.toSecuredDetails
import com.sphereon.di.app.AppGraph
import com.sphereon.di.context.ClassifiedPrincipalInput
import com.sphereon.di.context.IdentityConstants
import com.sphereon.di.context.IdentityMetadata
import com.sphereon.di.context.IdentityResolutionInput
import com.sphereon.di.context.IdentityResolutionResult
import com.sphereon.di.context.PrincipalInputString
import com.sphereon.di.context.PreauthorizedServiceBearer
import com.sphereon.di.context.PrincipalType
import com.sphereon.di.context.ResolutionSource
import com.sphereon.di.context.SecuredTenantContextDetails
import com.sphereon.ktor.server.inject.AuthoritativePrincipalTypeAttribute
import com.sphereon.ktor.server.inject.BaseTenantIdAttribute
import com.sphereon.ktor.server.inject.ValidatedJwtClaimsAttribute
import com.sphereon.ktor.server.inject.ValidatedServiceAudienceAttribute
import com.sphereon.ktor.server.inject.ValidatedRequestSecureDetailsFactory
import com.sphereon.core.defaults.context.ValidatedJwtClaimsInput
import com.sphereon.ktor.server.inject.context.RequestScopedContext
import com.sphereon.ktor.server.inject.requestContext
import com.sphereon.ktor.server.inject.resolver.PrincipalResolver
import com.sphereon.ktor.server.inject.resolver.TenantResolver
import com.sphereon.ktor.server.inject.sessionInstance
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.header
import io.ktor.util.AttributeKey
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/**
 * Interceptor that resolves and sets up user context and session for each Ktor request.
 *
 * This interceptor is automatically installed by the KotlinInject plugin. It performs the following:
 * 1. Resolves tenant from the request (via [TenantResolver])
 * 2. Resolves principal from the request (via [PrincipalResolver])
 * 3. Creates or retrieves the user context (ID-based, no active state)
 * 4. Creates or retrieves the session (using a generated session ID)
 * 5. Stores instances in [RequestScopedContext] as a call attribute
 *
 * **Key Design Principles:**
 * - ID-based resolution (never sets makeActive = true)
 * - Thread-safe via call-scoped attributes
 * - No global state
 * - Creates contexts/sessions lazily
 * - Uses IDK scoped loggers (AppLogManager) for consistency
 * - Multiplatform compatible (JVM, JavaScript, Native, GraalVM)
 *
 * @property appGraph The root application graph
 * @property tenantResolver Resolver for extracting tenant information
 * @property principalResolver Resolver for extracting principal information
 */
class UserContextInterceptor(
    private val appGraph: AppGraph,
    private val tenantResolver: TenantResolver,
    private val principalResolver: PrincipalResolver,
    private val validatedSecureDetailsFactory: ValidatedRequestSecureDetailsFactory? = null,
) {
    companion object {
        /**
         * Attribute key for storing the request-scoped context.
         */
        val RequestContextKey = AttributeKey<RequestScopedContext>("RequestScopedContext")
        private const val LOG_TAG = "KotlinInjectPlugin"

        /**
         * Generate a unique session ID using Kotlin's multiplatform UUID support.
         */
        @OptIn(ExperimentalUuidApi::class)
        private fun generateSessionId(): String = Uuid.random().toString()
    }

    // Get the app-scoped logger from the graph
    private val appLogger: LogService by lazy {
        (appGraph as CoreApiAppExtensionGraph).appLogManager.withTag(LOG_TAG)
    }

    private val coreGraph: CoreApiAppExtensionGraph by lazy {
        appGraph as CoreApiAppExtensionGraph
    }

    suspend fun intercept(call: ApplicationCall): RequestScopedContext {
        try {
            // Resolve tenant and authoritative token identity first. A validated protocol token
            // may intentionally establish tenant authority without naming a user principal (for
            // example an OID4VCI access token carrying only authorization_details). In that case
            // the authoritative ANONYMOUS result maps to the framework's anonymous sentinel; it
            // must not be forced through a user-claim resolver that requires `sub` or `email`.
            val tenantInput = tenantResolver.resolve(call)
            val validatedJwt = call.attributes.getOrNull(ValidatedJwtClaimsAttribute)
            val authoritativePrincipalType = call.attributes.getOrNull(AuthoritativePrincipalTypeAttribute)
            val identityResolution =
                validatedJwt?.let {
                    coreGraph.identityResolutionPipeline
                        .resolve(IdentityResolutionInput(tokenClaims = it.claimsInput.claims))
                        .withAuthoritativePrincipalType(authoritativePrincipalType)
                }
            val transportPrincipalInput = if (identityResolution == null) principalResolver.resolve(call) else null
            val effectiveIdentityResolution =
                identityResolution?.withAnonymousPrincipalSentinel()
                    ?: run {
                        val anonymousInput = requireNotNull(transportPrincipalInput)
                        IdentityResolutionResult(
                            tenantId = tenantInput.tenant.toString(),
                            principalId = anonymousInput.principal.toString(),
                            principalType =
                                if (anonymousInput.principal == IdentityConstants.ANONYMOUS_PRINCIPAL_ID) {
                                    PrincipalType.ANONYMOUS
                                } else {
                                    PrincipalType.USER
                                },
                            metadata = IdentityMetadata(resolvedFrom = ResolutionSource.DEFAULT),
                        )
                    }
            val principalInput =
                identityResolution?.let {
                    ResolvedPrincipalInput(
                        principal =
                            requireNotNull(effectiveIdentityResolution.principalId) {
                                "Authoritative ${effectiveIdentityResolution.principalType} identity has no principal"
                            },
                        principalType = effectiveIdentityResolution.principalType,
                    )
                } ?: requireNotNull(transportPrincipalInput)

            appLogger.debug("Processing request [tenant=${tenantInput.tenant}, principal=${principalInput.principal}]")

            // Create or get user context (ID-based, no active state)
            val contextInstance =
                coreGraph.userContextManager.createOrGetFromResolvedInputs(
                    tenantInput = tenantInput,
                    principalInput = principalInput,
                    identityResolution = effectiveIdentityResolution,
                    makeActive = false, // ID-based resolution, no global active state
                )

            val resolvedTenantId = contextInstance.context.tenant.tenantId
            val previouslyResolvedTenantId = call.attributes.getOrNull(BaseTenantIdAttribute)
            require(previouslyResolvedTenantId == null || previouslyResolvedTenantId == resolvedTenantId) {
                "Resolved tenant mismatch between authenticated ingress stages"
            }
            if (previouslyResolvedTenantId == null) {
                call.attributes.put(BaseTenantIdAttribute, resolvedTenantId)
            }

            // Generate a unique session ID for this request (multiplatform compatible)
            // In production, you might want to use a session cookie or similar
            val sessionId = generateSessionId()
            // Honour the inbound X-Correlation-Id header if present so audit /
            // log lines from this request thread back to the calling system;
            // otherwise the session id is its own natural correlation anchor.
            val correlationId = call.request.header("X-Correlation-Id") ?: sessionId

            // When an auth/tenant-resolution plugin validated a bearer token for this
            // call, project it into the session's secure details so commands can read
            // the validated JWT (and its authorization claims, e.g. `roles`) through
            // `execution.sessionContext.context.secureDetails?.jwt`. Per-session by
            // design: the user context above is cached per tenant+principal and must
            // not carry one request's token.
            // A bearer the host ingress verified for this service's own audience is a
            // pre-authorized service bearer for exactly that audience.
            val serviceAudience = call.attributes.getOrNull(ValidatedServiceAudienceAttribute)?.takeIf { it.isNotBlank() }
            val secureDetails = projectValidatedRequestSecureDetails(
                call, validatedJwt, effectiveIdentityResolution.copy(tenantId = resolvedTenantId),
                serviceAudience, validatedSecureDetailsFactory,
            )

            // Create or get session (using generated session ID). The principal
            // classification resolved by the identity pipeline rides along so the
            // session does not silently downgrade e.g. WORKLOAD to USER.
            val sessionInstance =
                contextInstance.sessionContextManager.createOrGetFromId(
                    sessionId = sessionId,
                    correlationId = correlationId,
                    makeActive = false, // ID-based resolution, no global active state
                    secureDetails = secureDetails,
                    principalType = effectiveIdentityResolution.principalType,
                )

            // Store context in call attributes
            val requestContext =
                RequestScopedContext(
                    userInstance = contextInstance,
                    sessionInstance = sessionInstance,
                )
            call.attributes.put(RequestContextKey, requestContext)

            appLogger.trace("Context set: userContext=${contextInstance.contextId}, session=${sessionInstance.sessionId}")
            return requestContext
        } catch (expected: Exception) {
            appLogger.error("Error processing request in UserContextInterceptor: ${expected.message}", expected)
            throw expected
        }
    }
}

/** A custom projection must retain the validated credential and its original validity window. */
internal fun projectValidatedRequestSecureDetails(
    call: ApplicationCall,
    validatedJwt: ValidatedJwtClaimsInput?,
    identity: IdentityResolutionResult,
    serviceAudience: String?,
    factory: ValidatedRequestSecureDetailsFactory?,
): SecuredTenantContextDetails? {
    val base = validatedJwt?.toSecuredDetails() ?: return null
    if (factory == null) {
        return serviceAudience?.let { ValidatedServiceAudienceSecuredDetails(base, it) } ?: base
    }
    val projected = factory.create(call, validatedJwt, identity)
    require(projected.jwt == base.jwt && projected.iss == base.iss &&
        projected.validFrom == base.validFrom && projected.validUntil == base.validUntil) {
        "Host secure-details projection changed the validated credential"
    }
    // Do not wrap this result in a base-interface decorator: that would erase stronger host
    // provenance interfaces. The host owns its exact service-audience policy on this path.
    return projected
}

/** A token-derived principal whose classification is already decided, so it is never defaulted to USER. */
private data class ResolvedPrincipalInput(
    override val principal: String,
    override val principalType: PrincipalType,
) : PrincipalInputString,
    ClassifiedPrincipalInput

/**
 * Applies the host's ingress classification for a validated token. An anonymous token identity has
 * no principal to reclassify and is left as is.
 */
internal fun IdentityResolutionResult.withAuthoritativePrincipalType(
    authoritativePrincipalType: PrincipalType?,
): IdentityResolutionResult =
    if (authoritativePrincipalType == null ||
        authoritativePrincipalType == principalType ||
        principalType == PrincipalType.ANONYMOUS
    ) {
        this
    } else {
        copy(principalType = authoritativePrincipalType)
    }

internal fun IdentityResolutionResult.withAnonymousPrincipalSentinel(): IdentityResolutionResult =
    if (principalId == null && principalType == PrincipalType.ANONYMOUS) {
        copy(principalId = IdentityConstants.ANONYMOUS_PRINCIPAL_ID)
    } else {
        this
    }

/**
 * Secure details of a bearer the host ingress verified was issued for this service's own audience.
 * It authorizes exactly that audience, never any other value in the token's `aud` claim.
 */
internal class ValidatedServiceAudienceSecuredDetails(
    private val delegate: SecuredTenantContextDetails,
    private val audience: String,
) : SecuredTenantContextDetails by delegate, PreauthorizedServiceBearer {
    override fun authorizesServiceAudience(audience: String): Boolean = audience.isNotBlank() && audience == this.audience

    override fun toString(): String = "ValidatedServiceAudienceSecuredDetails([REDACTED])"
}
