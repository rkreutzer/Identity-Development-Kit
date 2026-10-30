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
import com.sphereon.core.api.log.AppLogManager
import com.sphereon.core.api.log.LogService
import com.sphereon.core.defaults.context.DefaultPrincipalInputString
import com.sphereon.core.defaults.context.JwtClaimsInput
import com.sphereon.core.defaults.context.markValidated
import com.sphereon.di.app.AppGraph
import com.sphereon.di.context.BasicSecuredDetails
import com.sphereon.di.context.ClassifiedPrincipalInput
import com.sphereon.di.context.IdentityConstants
import com.sphereon.di.context.IdentityMetadata
import com.sphereon.di.context.IdentityResolutionInput
import com.sphereon.di.context.IdentityResolutionPipeline
import com.sphereon.di.context.IdentityResolutionResult
import com.sphereon.di.context.PrincipalType
import com.sphereon.di.context.ResolutionSource
import com.sphereon.di.context.TenantContextData
import com.sphereon.di.context.UserContext
import com.sphereon.di.context.UserContextInstance
import com.sphereon.di.context.UserContextManager
import com.sphereon.di.session.SessionContextManager
import com.sphereon.di.session.SessionInstance
import com.sphereon.ktor.server.inject.AuthoritativePrincipalTypeAttribute
import com.sphereon.ktor.server.inject.ValidatedJwtClaimsAttribute
import com.sphereon.ktor.server.inject.ValidatedServiceAudienceAttribute
import com.sphereon.ktor.server.inject.ValidatedRequestSecureDetailsFactory
import com.sphereon.core.defaults.context.toSecuredDetails
import com.sphereon.di.context.PreauthorizedServiceBearer
import com.sphereon.di.context.SecuredTenantContextDetails
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import com.sphereon.ktor.server.inject.resolver.FixedTenantResolver
import com.sphereon.ktor.server.inject.resolver.PrincipalResolver
import io.ktor.http.Headers
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.ApplicationRequest
import io.ktor.util.Attributes
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonPrimitive
import java.lang.reflect.Method
import java.lang.reflect.Proxy
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertSame
import kotlin.test.assertFailsWith

/**
 * The identity pipeline is the single authority for principal classification.
 * Once it resolves a request as WORKLOAD, the session opened for that request
 * must carry the same classification: the interceptor has to use the 5-arg
 * [SessionContextManager.createOrGetFromId] overload instead of one of the
 * defaulting overloads that would silently downgrade to USER.
 */
class UserContextInterceptorPrincipalTypeTest {
    private interface HostValidationEvidence

    private class HostDetails(
        delegate: SecuredTenantContextDetails,
        private val serviceAudience: String?,
    ) : SecuredTenantContextDetails by delegate, HostValidationEvidence, PreauthorizedServiceBearer {
        override fun authorizesServiceAudience(audience: String): Boolean =
            audience.isNotBlank() && audience == serviceAudience
    }

    @Test
    fun customValidatedProjectionSurvivesUserAndWorkloadSessionCreation() = runTest {
        for (type in listOf(PrincipalType.USER, PrincipalType.WORKLOAD)) {
            var projected: SecuredTenantContextDetails? = null
            val captured = interceptWorkloadToken(
                authoritativePrincipalType = type,
                validatedServiceAudience = if (type == PrincipalType.WORKLOAD) "receiver" else null,
                secureDetailsFactory = ValidatedRequestSecureDetailsFactory { _, validated, identity ->
                    assertEquals(type, identity.principalType)
                    assertEquals("platform", identity.tenantId)
                    HostDetails(requireNotNull(validated.toSecuredDetails()), "receiver".takeIf { type == PrincipalType.WORKLOAD })
                        .also { projected = it }
                },
            )
            val details = captured.sessionArgs[3] as SecuredTenantContextDetails
            assertSame(projected, details)
            assertTrue(details is HostValidationEvidence)
            val bearer = details as PreauthorizedServiceBearer
            assertEquals(type == PrincipalType.WORKLOAD, bearer.authorizesServiceAudience("receiver"))
            assertFalse(bearer.authorizesServiceAudience("other"))
        }
    }

    @Test
    fun customProjectionCannotReplaceBearerIssuerOrLifetime() = runTest {
        val replacements: List<(SecuredTenantContextDetails) -> SecuredTenantContextDetails> = listOf(
            { base -> BasicSecuredDetails(jwt = "another", iss = base.iss, validFrom = base.validFrom, validUntil = base.validUntil) },
            { base -> BasicSecuredDetails(jwt = base.jwt, iss = "https://other.example", validFrom = base.validFrom, validUntil = base.validUntil) },
            { base -> BasicSecuredDetails(jwt = base.jwt, iss = base.iss, validFrom = base.validFrom - 1, validUntil = base.validUntil) },
            { base -> BasicSecuredDetails(jwt = base.jwt, iss = base.iss, validFrom = base.validFrom, validUntil = base.validUntil + 1) },
        )
        for (replacement in replacements) {
            assertFailsWith<IllegalArgumentException> {
                interceptWorkloadToken(
                    authoritativePrincipalType = PrincipalType.USER,
                    secureDetailsFactory = ValidatedRequestSecureDetailsFactory { _, validated, _ ->
                        replacement(requireNotNull(validated.toSecuredDetails()))
                    },
                )
            }
        }
    }
    @Test
    fun anonymousTokenIdentityUsesFrameworkPrincipalSentinel() {
        val resolution =
            IdentityResolutionResult(
                tenantId = "tenant-1",
                principalId = null,
                principalType = PrincipalType.ANONYMOUS,
                metadata = IdentityMetadata(resolvedFrom = ResolutionSource.TOKEN),
            )

        val normalized = resolution.withAnonymousPrincipalSentinel()

        assertEquals(IdentityConstants.ANONYMOUS_PRINCIPAL_ID, normalized.principalId)
        assertEquals("tenant-1", normalized.tenantId)
        assertEquals(PrincipalType.ANONYMOUS, normalized.principalType)
    }

    @Test
    fun namedIdentityIsNotRewritten() {
        val resolution =
            IdentityResolutionResult(
                tenantId = "tenant-1",
                principalId = "service-1",
                principalType = PrincipalType.WORKLOAD,
                metadata = IdentityMetadata(resolvedFrom = ResolutionSource.TOKEN),
            )

        assertSame(resolution, resolution.withAnonymousPrincipalSentinel())
    }

    @Test
    fun workloadClassificationFromPipelineReachesSessionCreation() =
        runTest {
            val captured = interceptWorkloadToken(authoritativePrincipalType = null)

            assertEquals(PrincipalType.WORKLOAD, captured.identityResolution.principalType)
            assertEquals(PrincipalType.WORKLOAD, (captured.principalInput as ClassifiedPrincipalInput).principalType)
            val arguments = captured.sessionArgs
            assertEquals(false, arguments[2])
            assertEquals("validated-workload-token", (arguments[3] as BasicSecuredDetails).jwt)
            assertEquals(PrincipalType.WORKLOAD, arguments[4])
        }

    /**
     * When the host ingress validated that the bearer was issued for this service's own audience,
     * the session carries that as a pre-authorized service bearer for exactly that audience, the
     * same contract the binary transport ingress gives command code.
     */
    @Test
    fun validatedServiceAudienceAuthorizesExactlyThatAudience() =
        runTest {
            val captured = interceptWorkloadToken(authoritativePrincipalType = null, validatedServiceAudience = "enterprise-tenant-as")

            val details = captured.sessionArgs[3] as SecuredTenantContextDetails
            assertEquals("validated-workload-token", details.jwt)
            val bearer = details as PreauthorizedServiceBearer
            assertTrue(bearer.authorizesServiceAudience("enterprise-tenant-as"))
            assertFalse(bearer.authorizesServiceAudience("enterprise-platform"))
            assertFalse(bearer.authorizesServiceAudience(""))
        }

    @Test
    fun bearerWithoutValidatedServiceAudienceIsNotPreauthorized() =
        runTest {
            val captured = interceptWorkloadToken(authoritativePrincipalType = null)

            assertFalse(captured.sessionArgs[3] is PreauthorizedServiceBearer)
        }

    /**
     * An external tenant service client token is classified WORKLOAD by the pipeline, but the host
     * transport treats it as a tenant principal. The context the interceptor opens must carry the
     * host's classification, or the command transport opening the same `tenant:principal` context
     * afterwards fails with "Principal classification mismatch for existing context".
     */
    @Test
    fun hostIngressClassificationOverridesPipelineForUserAndSessionContext() =
        runTest {
            val captured = interceptWorkloadToken(authoritativePrincipalType = PrincipalType.USER)

            assertEquals(PrincipalType.USER, captured.identityResolution.principalType)
            assertEquals("service-crypto", captured.identityResolution.principalId)
            val principalInput = captured.principalInput as ClassifiedPrincipalInput
            assertEquals("service-crypto", principalInput.principal)
            assertEquals(PrincipalType.USER, principalInput.principalType)
            assertEquals(PrincipalType.USER, captured.sessionArgs[4])
        }

    @Test
    fun hostClassificationNeverReclassifiesAnAnonymousTokenIdentity() {
        val anonymous =
            IdentityResolutionResult(
                tenantId = "tenant-1",
                principalId = null,
                principalType = PrincipalType.ANONYMOUS,
                metadata = IdentityMetadata(resolvedFrom = ResolutionSource.TOKEN),
            )

        assertSame(anonymous, anonymous.withAuthoritativePrincipalType(PrincipalType.USER))
    }

    private class CapturedInterception(
        val identityResolution: IdentityResolutionResult,
        val principalInput: Any,
        val sessionArgs: Array<out Any?>,
    )

    private suspend fun interceptWorkloadToken(
        authoritativePrincipalType: PrincipalType?,
        validatedServiceAudience: String? = null,
        secureDetailsFactory: ValidatedRequestSecureDetailsFactory? = null,
    ): CapturedInterception {
        val workloadResolution =
            IdentityResolutionResult(
                tenantId = "platform",
                principalId = "service-crypto",
                principalType = PrincipalType.WORKLOAD,
                metadata = IdentityMetadata(resolvedFrom = ResolutionSource.TOKEN),
            )

        var capturedIdentityResolution: IdentityResolutionResult? = null
        var capturedPrincipalInput: Any? = null
        var capturedSessionArgs: Array<out Any?>? = null

        val sessionInstance =
            proxy<SessionInstance> { method, _ ->
                when (method.name) {
                    "getSessionId" -> "session-under-test"
                    else -> error("Unexpected SessionInstance call: ${method.name}")
                }
            }
        val sessionContextManager =
            proxy<SessionContextManager> { method, arguments ->
                if (method.name == "createOrGetFromId" && arguments?.size == 5) {
                    capturedSessionArgs = arguments
                    sessionInstance
                } else {
                    error("Unexpected SessionContextManager call: ${method.name}")
                }
            }
        val tenantData =
            object : TenantContextData {
                override val tenantId: String = "platform"
            }
        val userContext =
            proxy<UserContext> { method, _ ->
                when (method.name) {
                    "getTenant" -> tenantData
                    else -> error("Unexpected UserContext call: ${method.name}")
                }
            }
        val contextInstance =
            proxy<UserContextInstance> { method, _ ->
                when (method.name) {
                    "getContext" -> userContext
                    "getContextId" -> "user-context-under-test"
                    "getSessionContextManager" -> sessionContextManager
                    else -> error("Unexpected UserContextInstance call: ${method.name}")
                }
            }
        val userContextManager =
            proxy<UserContextManager> { method, arguments ->
                if (method.name == "createOrGetFromResolvedInputs" && arguments?.size == 4) {
                    capturedPrincipalInput = arguments[1]
                    capturedIdentityResolution = arguments[2] as IdentityResolutionResult
                    contextInstance
                } else {
                    error("Unexpected UserContextManager call: ${method.name}")
                }
            }

        val logService = proxy<LogService> { _, _ -> null }
        val appLogManager =
            proxy<AppLogManager> { method, _ ->
                when (method.name) {
                    "withTag" -> logService
                    else -> error("Unexpected AppLogManager call: ${method.name}")
                }
            }
        val pipeline =
            object : IdentityResolutionPipeline {
                override suspend fun resolve(input: IdentityResolutionInput): IdentityResolutionResult = workloadResolution
            }
        val appGraph =
            Proxy.newProxyInstance(
                AppGraph::class.java.classLoader,
                arrayOf(AppGraph::class.java, CoreApiAppExtensionGraph::class.java),
            ) { _, method, _ ->
                when (method.name) {
                    "getAppLogManager" -> appLogManager
                    "getIdentityResolutionPipeline" -> pipeline
                    "getUserContextManager" -> userContextManager
                    else -> error("Unexpected AppGraph call: ${method.name}")
                }
            } as AppGraph

        val attributes = Attributes()
        attributes.put(
            ValidatedJwtClaimsAttribute,
            JwtClaimsInput(
                claims =
                    mapOf(
                        "sub" to JsonPrimitive("service-crypto"),
                        "azp" to JsonPrimitive("service-crypto"),
                        "iss" to JsonPrimitive("https://issuer.example"),
                        "iat" to JsonPrimitive(1_700_000_000),
                        "exp" to JsonPrimitive(1_700_003_600),
                    ),
                rawToken = "validated-workload-token",
            ).markValidated(),
        )
        authoritativePrincipalType?.let { attributes.put(AuthoritativePrincipalTypeAttribute, it) }
        validatedServiceAudience?.let { attributes.put(ValidatedServiceAudienceAttribute, it) }
        val request =
            proxy<ApplicationRequest> { method, _ ->
                when (method.name) {
                    "getHeaders" -> Headers.Empty
                    else -> error("Unexpected ApplicationRequest call: ${method.name}")
                }
            }
        val call =
            proxy<ApplicationCall> { method, _ ->
                when (method.name) {
                    "getAttributes" -> attributes
                    "getRequest" -> request
                    else -> error("Unexpected ApplicationCall call: ${method.name}")
                }
            }

        val interceptor =
            UserContextInterceptor(
                appGraph = appGraph,
                validatedSecureDetailsFactory = secureDetailsFactory,
                tenantResolver = FixedTenantResolver("platform"),
                principalResolver =
                    object : PrincipalResolver {
                        override fun resolve(call: ApplicationCall) = DefaultPrincipalInputString("service-crypto")
                    },
            )

        interceptor.intercept(call)

        return CapturedInterception(
            identityResolution = requireNotNull(capturedIdentityResolution),
            principalInput = requireNotNull(capturedPrincipalInput),
            sessionArgs = requireNotNull(capturedSessionArgs),
        )
    }
}

private inline fun <reified T> proxy(crossinline handler: (method: Method, args: Array<out Any?>?) -> Any?): T =
    Proxy.newProxyInstance(
        T::class.java.classLoader,
        arrayOf(T::class.java),
    ) { proxyInstance, method, args ->
        when (method.name) {
            "toString" -> "proxy<${T::class.simpleName}>"
            "hashCode" -> System.identityHashCode(proxyInstance)
            "equals" -> proxyInstance === args?.get(0)
            else -> handler(method, args)
        }
    } as T
