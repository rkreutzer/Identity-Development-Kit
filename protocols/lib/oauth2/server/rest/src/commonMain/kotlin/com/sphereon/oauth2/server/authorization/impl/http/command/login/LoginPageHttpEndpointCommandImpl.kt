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

// Role-neutral OAuth REST capability. Executable server startup remains in services-oauth2-as-rest.
package com.sphereon.oauth2.server.authorization.impl.http.command.login

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.http.GenericHttpRequest
import com.sphereon.core.api.http.GenericHttpResponse
import com.sphereon.core.api.http.command.HttpEndpointCommand
import com.sphereon.core.api.http.command.HttpEndpointCommandAdapter
import com.sphereon.di.context.IdentityConstants
import com.sphereon.di.session.SessionScope
import com.sphereon.oauth2.common.config.OAuth2ServerInstanceIdProvider
import com.sphereon.oauth2.common.config.OAuth2ServersConfigProvider
import com.sphereon.oauth2.server.authorization.command.login.LoginPageHttpEndpointCommand
import com.sphereon.oauth2.server.authorization.impl.http.OAuth2ServerBaseUrlResolver
import com.sphereon.oauth2.server.authorization.impl.http.ResponseCategory
import com.sphereon.oauth2.server.authorization.impl.http.effectiveScheme
import com.sphereon.oauth2.server.authorization.impl.http.isSameOriginCallback
import com.sphereon.oauth2.server.authorization.impl.http.loginCsrfCookieHeader
import com.sphereon.oauth2.server.authorization.impl.http.loginCsrfCookiePath
import com.sphereon.oauth2.server.authorization.impl.http.oauth2ErrorResponse
import com.sphereon.oauth2.server.authorization.impl.http.withSecurityHeaders
import com.sphereon.oauth2.server.authorization.provider.AcceptLanguageNegotiation
import com.sphereon.oauth2.server.authorization.provider.FederationLoginOption
import com.sphereon.oauth2.server.authorization.provider.LoginCsrfTokenizer
import com.sphereon.oauth2.server.authorization.provider.LoginPageContext
import com.sphereon.oauth2.server.authorization.provider.LoginPageRenderer
import com.sphereon.oauth2.server.authorization.provider.LoginPageThemeProvider
import com.sphereon.oauth2.server.authorization.provider.LoginPageThemeSnapshot
import com.sphereon.oauth2.server.authorization.storage.PendingAuthorizationSessionStore
import dev.zacsweers.metro.ContributesIntoMap
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.Provider
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.StringKey
import dev.zacsweers.metro.binding
import kotlinx.coroutines.CancellationException
import kotlinx.serialization.json.Json

/**
 * HTTP shell over [LoginPageRenderer] for `GET /login`. Reads `session_id`, optional `return_url`,
 * optional `error`, optional `login_hint` from query parameters; negotiates a locale from the
 * `Accept-Language` header per RFC 7231 §5.3.5 (q-value sorted, `q=0` rejections honoured,
 * language-tag prefix matching); calls the renderer; and wraps the result in a 200 response with
 * `Cache-Control: no-store` so the page is never cached in shared proxies (it carries a session id
 * and may carry a flash error).
 */
@Inject
@SingleIn(SessionScope::class)
@ContributesIntoMap(SessionScope::class, binding = binding<HttpEndpointCommand>())
@StringKey(LoginPageHttpEndpointCommand.COMMAND_ID)
class LoginPageHttpEndpointCommandImpl(
    execution: SessionExecution,
    private val loginPageRenderer: LoginPageRenderer,
    private val asInstanceIdProvider: OAuth2ServerInstanceIdProvider,
    private val configProvider: OAuth2ServersConfigProvider,
    private val baseUrlResolver: OAuth2ServerBaseUrlResolver,
    private val csrfTokenizer: LoginCsrfTokenizer,
    private val pendingAuthorizationSessionStore: PendingAuthorizationSessionStore,
    // Theming is strictly optional: assemblies without a [LoginPageThemeProvider] (platform
    // theme adapter) render the neutral default page.
    private val themeProvider: Provider<LoginPageThemeProvider>? = null,
) : HttpEndpointCommandAdapter(
        id = LoginPageHttpEndpointCommand.COMMAND_ID,
        execution = execution,
        endpoint = LoginPageHttpEndpointCommand.ENDPOINT,
    ),
    LoginPageHttpEndpointCommand {
    private val json =
        Json {
            prettyPrint = false
            ignoreUnknownKeys = true
        }

    override suspend fun doExecute(
        args: GenericHttpRequest,
        applyDuring: (GenericHttpRequest) -> GenericHttpRequest,
    ): IdkResult<GenericHttpResponse, IdkError> {
        val request = applyDuring(args)

        @Suppress("UNCHECKED_CAST")
        val params = request.queryParameters.filterValues { it != null } as Map<String, String>
        val sessionId =
            params["session_id"]
                ?: return Ok(oauth2ErrorResponse(400, "invalid_request", "Missing session_id parameter", json))
        val trustedBase = baseUrlResolver.resolveBaseUrl(request, configProvider).trimEnd('/')
        val defaultReturnUrl = "$trustedBase/authorize/callback?session_id=$sessionId"
        val requestedReturnUrl = params["return_url"]
        val returnUrl =
            when {
                requestedReturnUrl == null -> defaultReturnUrl
                isSameOriginCallback(requestedReturnUrl, trustedBase) -> requestedReturnUrl
                else -> defaultReturnUrl
            }
        val errorParam = params["error"]
        val errorMessage = if (errorParam == "invalid_credentials") errorParam else null
        val loginHint = params["login_hint"]
        val locale = negotiateLocale(request.headers["accept-language"] ?: request.headers["Accept-Language"])
        val loginConfig = configProvider.serverConfig.login
        val pending = pendingAuthorizationSessionStore.findById(sessionId)
        if (pending.isErr) {
            return Ok(oauth2ErrorResponse(503, "temporarily_unavailable", "Authorization transaction could not be checked", json))
        }
        if (pending.value == null) {
            return Ok(oauth2ErrorResponse(400, "invalid_request", "Unknown or expired authorization transaction", json))
        }
        val routeDecision = pending.value!!.authenticationRoute
            ?: return Ok(oauth2ErrorResponse(400, "invalid_request", "Authorization transaction has no authentication route", json))
        val csrf = try {
            csrfTokenizer.mint(sessionId)
        } catch (e: CancellationException) {
            throw e
        } catch (e: IllegalArgumentException) {
            return Ok(oauth2ErrorResponse(400, "invalid_request", "Unknown or expired authorization transaction", json))
        } catch (e: Exception) {
            return Ok(oauth2ErrorResponse(503, "temporarily_unavailable", "Login challenge could not be created", json))
        }
        val federationOptions = routeDecision.eligibleBindings.map {
            FederationLoginOption(id = it.bindingId, displayName = it.displayName)
        }
        val tenantId =
            runCatching { execution.tenantId }
                .getOrNull()
                ?.takeIf { it.isNotBlank() && it != IdentityConstants.ANONYMOUS_TENANT_ID }
        val asInstanceId = asInstanceIdProvider.currentAsInstanceId() ?: DEFAULT_AS_INSTANCE_ID
        val theming =
            if (loginConfig.themeResolutionEnabled) {
                resolveThemingOrNeutral(tenantId, asInstanceId)
            } else {
                LoginPageThemeSnapshot()
            }
        val ctx =
            LoginPageContext(
                asInstanceId = asInstanceId,
                tenantId = tenantId,
                sessionId = sessionId,
                returnUrl = returnUrl,
                loginHint = loginHint,
                errorMessage = errorMessage,
                locale = locale,
                tabId = csrf.tabId,
                sessionCode = csrf.sessionCode,
                notice = configProvider.serverConfig.loginNotice,
                federationOptions = federationOptions,
                formActionBase = trustedBase,
                showPasswordForm = routeDecision.localLoginAllowed,
                showWebAuthn = configProvider.serverConfig.webAuthn.enabled,
                showWallet = loginConfig.showWallet && !loginConfig.walletAuthorizationUrl.isNullOrBlank(),
                walletAuthorizationUrl = loginConfig.walletAuthorizationUrl,
                defaultMethod = loginConfig.defaultMethod,
                display = params["display"]?.takeIf { it in SUPPORTED_DISPLAY_VALUES } ?: "page",
                acrValues = params["acr_values"]?.split(' ')?.map(String::trim)?.filter(String::isNotEmpty).orEmpty(),
                forceReauth = params["force_reauth"].toBoolean(),
                cspNonce = csrf.sessionCode,
                lightBranding = theming.lightBranding,
                darkBranding = theming.darkBranding,
            )
        val rendered = loginPageRenderer.render(ctx)
        if (!rendered.isOk) {
            return Ok(oauth2ErrorResponse(500, "server_error", rendered.error.message.defaultMessage, json))
        }
        val response = rendered.value
        val secure = request.effectiveScheme(configProvider) == "https"
        return Ok(
            GenericHttpResponse(
                statusCode = 200,
                headers =
                    mapOf(
                        "Content-Type" to response.contentType,
                        "Cache-Control" to "no-store",
                        "Pragma" to "no-cache",
                        "Set-Cookie" to loginCsrfCookieHeader(csrf.tabId, secure, loginCsrfCookiePath(trustedBase)),
                    ),
                body = response.html,
            ).withSecurityHeaders(
                ResponseCategory.HTML,
                response.cspNonce,
                imageOrigins =
                    crossOriginImageOrigins(theming.imageUris, trustedBase) +
                        response.imageOrigins.mapNotNull(::httpOriginOrNull),
            ),
        )
    }

    @Suppress("TooGenericExceptionCaught")
    private suspend fun resolveThemingOrNeutral(
        tenantId: String?,
        asInstanceId: String,
    ): LoginPageThemeSnapshot {
        val provider = themeProvider ?: return LoginPageThemeSnapshot()
        return try {
            provider.invoke().resolve(tenantId, asInstanceId)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            execution.log.logManager
                .withTag("LoginPageHttpEndpointCommand")
                .warn("Theme resolution failed for tenant '$tenantId'; rendering the neutral login page: ${e.message}")
            LoginPageThemeSnapshot()
        }
    }

    private fun crossOriginImageOrigins(
        imageUris: List<String>,
        trustedBase: String,
    ): Set<String> {
        if (imageUris.isEmpty()) return emptySet()
        val baseOrigin = httpOriginOrNull(trustedBase)
        return imageUris
            .mapNotNull(::httpOriginOrNull)
            .filterTo(mutableSetOf()) { it != baseOrigin }
    }

    private fun httpOriginOrNull(url: String): String? {
        val schemeEnd = url.indexOf("://")
        if (schemeEnd <= 0) return null
        val scheme = url.substring(0, schemeEnd).lowercase()
        if (scheme != "http" && scheme != "https") return null
        val hostPort =
            url
                .substring(schemeEnd + 3)
                .takeWhile { it != '/' && it != '?' && it != '#' }
        if (hostPort.isEmpty() || !HOST_PORT_PATTERN.matches(hostPort)) return null
        return "$scheme://${hostPort.lowercase()}"
    }

    private fun negotiateLocale(acceptLanguage: String?): String =
        AcceptLanguageNegotiation.negotiate(
            header = acceptLanguage,
            supportedLocales = SUPPORTED_LOCALES,
            defaultLocale = DEFAULT_LOCALE,
        )

    companion object {
        private const val DEFAULT_LOCALE: String = "en"
        private const val DEFAULT_AS_INSTANCE_ID: String = "default"
        private val SUPPORTED_LOCALES: Set<String> = setOf("en", "nl")
        private val SUPPORTED_DISPLAY_VALUES: Set<String> = setOf("page", "popup", "touch", "wap")
        private val HOST_PORT_PATTERN = Regex("""(?:[A-Za-z0-9.-]+|\[[0-9A-Fa-f:]+\])(?::\d{1,5})?""")
    }
}
