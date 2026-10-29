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
package com.sphereon.ktor.http.client.provider

import com.sphereon.core.api.context.SessionExecution
import com.sphereon.di.session.SessionScope
import com.sphereon.ktor.http.client.config.CaOpts
import com.sphereon.ktor.http.client.config.SslConfig
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import io.ktor.client.HttpClient
import io.ktor.client.engine.HttpClientEngine
import io.ktor.client.engine.okhttp.OkHttp
import io.ktor.client.plugins.cache.HttpCache
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.plugins.defaultRequest
import io.ktor.client.plugins.logging.Logging
import java.net.InetAddress
import java.io.ByteArrayInputStream
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import okhttp3.ConnectionSpec
import okhttp3.TlsVersion

/**
 * Default (crypto-free) JVM HTTP client factory.
 *
 * Supports platform trust plus governed PEM [CaOpts.resolvedCertificates]. Keystore-backed
 * mTLS / additional CAs require the KMS HTTP client factory on the classpath.
 */
@Inject
@SingleIn(SessionScope::class)
@ContributesBinding(SessionScope::class)
class HttpClientFactoryJvmImpl(
    private val execution: SessionExecution,
) : HttpClientFactory {
    private val log = execution.log.logManager.withTag("HttpClientFactory")

    internal var egressResolver: (String) -> List<InetAddress> = { host -> InetAddress.getAllByName(host).toList() }

    override fun createClient(options: HttpClientOptions): HttpClient {
        require(isSupportedOptions(options)) { "Provided http client options are not supported on this platform" }
        requireKmsNotRequired(options.sslConfig)

        with(options) {
            val engine =
                when (engine ?: getEngineTypeDefault()) {
                    HttpClientEngineType.CIO -> TODO("CIO engine is only supported via LegacyHttpClientFactory at present")
                    HttpClientEngineType.OKHTTP -> createOkHttpEngine(options)
                    HttpClientEngineType.DARWIN -> TODO("Jvm darwin not supported yet. Please use native, or CIO/OKHTTP with Jvm on MacOs")
                    HttpClientEngineType.JS -> TODO("JS engine is not supported on JVM, use CIO or OKHTTP")
                }

            return HttpClient(engine) {
                followRedirects = options.followRedirects
                if (enableHttpCache) {
                    install(HttpCache) {
                        httpCacheConfig?.invoke(this)
                    }
                }

                if (enableContentNegotiation) {
                    install(ContentNegotiation) {
                        contentNegotiationConfig?.invoke(this)
                    }
                }

                if (enableLogging) {
                    install(Logging) {
                        level = loggingConfig.toKtorHttpClientLogLevel()
                        sanitizeHeader { header -> header.isSensitiveHttpClientLogHeader() }
                    }
                }

                val defaultReq = options.defaultRequest
                if (defaultReq != null) {
                    defaultRequest(defaultReq)
                }

                additionalConfig?.invoke(this)

                // Keep the caller-selected option last so an arbitrary additionalConfig cannot
                // silently re-enable auto-follow for a governed (false) client.
                followRedirects = options.followRedirects
            }.also { client ->
                val validationPolicy = urlValidation
                if (validationPolicy != null) {
                    client.installUrlValidation(validationPolicy)
                }
            }
        }
    }

    override fun getEngineTypesSupported(): List<HttpClientEngineType> = listOf(HttpClientEngineType.CIO, HttpClientEngineType.OKHTTP)

    override fun getEngineTypeDefault(): HttpClientEngineType = HttpClientEngineType.OKHTTP

    override fun isSupportedOptions(options: HttpClientOptions): Boolean {
        if (!getEngineTypesSupported().contains(options.engine ?: getEngineTypeDefault())) {
            log.error("Http client engine type ${options.engine} not supported on Jvm")
            return false
        }
        return true
    }

    private fun requireKmsNotRequired(sslConfig: SslConfig) {
        if (sslConfig.client.isMtls()) {
            error(
                "mTLS client certificates require the KMS HTTP client factory " +
                    "(lib-data-link-http-client-kms-impl) on the classpath",
            )
        }
        if (sslConfig.server.ca.additionalCAs.isNotEmpty()) {
            error(
                "Keystore-backed additional CAs require the KMS HTTP client factory " +
                    "(lib-data-link-http-client-kms-impl) on the classpath",
            )
        }
    }

    private fun buildTrustManagers(caOpts: CaOpts): Set<X509TrustManager> {
        if (caOpts.includePlatformDefaults && !caOpts.hasCustomTrust()) {
            val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            tmf.init(null as KeyStore?)
            return tmf.trustManagers.filterIsInstance<X509TrustManager>().toSet()
        }

        val trustStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null, null) }

        if (caOpts.includePlatformDefaults) {
            val systemTmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            systemTmf.init(null as KeyStore?)
            systemTmf.trustManagers.filterIsInstance<X509TrustManager>().flatMap { it.acceptedIssuers.asIterable() }.forEachIndexed { idx, cert ->
                val alias = "system-$idx-${cert.subjectX500Principal.name.hashCode()}"
                trustStore.setCertificateEntry(alias, cert)
            }
        }

        val certificateFactory = CertificateFactory.getInstance("X.509")
        for (ca in caOpts.resolvedCertificates) {
            val certificate =
                ByteArrayInputStream(ca.certificatePem.encodeToByteArray()).use { input ->
                    certificateFactory.generateCertificate(input) as X509Certificate
                }
            val normalizedFingerprint = ca.certificateFingerprint.filter { it.isLetterOrDigit() }.lowercase()
            val (fingerprintAlgorithm, expectedFingerprint) =
                when {
                    normalizedFingerprint.startsWith("sha256") -> "SHA-256" to normalizedFingerprint.removePrefix("sha256")
                    normalizedFingerprint.startsWith("sha1") -> "SHA-1" to normalizedFingerprint.removePrefix("sha1")
                    normalizedFingerprint.length == SHA1_HEX_LENGTH -> "SHA-1" to normalizedFingerprint
                    else -> "SHA-256" to normalizedFingerprint
                }
            val actualFingerprint =
                MessageDigest
                    .getInstance(fingerprintAlgorithm)
                    .digest(certificate.encoded)
                    .joinToString("") { "%02x".format(it) }
            require(actualFingerprint == expectedFingerprint) {
                "Resolved CA certificate '${ca.certificateAlias}' fingerprint does not match its public material"
            }
            trustStore.setCertificateEntry("resolved-${ca.certificateAlias}", certificate)
        }

        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        tmf.init(trustStore)
        return tmf.trustManagers.filterIsInstance<X509TrustManager>().toSet()
    }

    private fun createOkHttpEngine(options: HttpClientOptions): HttpClientEngine {
        val sslConfig = options.sslConfig
        val trustManagers = buildTrustManagers(sslConfig.server.ca)
        val trustManager =
            trustManagers.singleOrNull()
                ?: error("Expected a single X509TrustManager from the configured trust store")
        val sslContext =
            SSLContext.getInstance("TLS").apply {
                init(null, arrayOf(trustManager), null)
            }
            // A policy that blocks address ranges is enforced on the addresses the connection actually resolves to,
            // not only on the host text, so names that map to internal addresses and DNS rebinding are refused.
            val egressGuard =
                options.urlValidation
                    ?.takeIf { it.blockPrivateNetworks || it.blockRfc1918 || it.blockSharedNetworks }
                    ?.let { policy ->
                        EgressGuard(
                            addressPolicy = { address -> EgressAddressPolicy.isAllowed(address, policy) },
                            resolver = egressResolver,
                        ).also { guard ->
                            guard.installResolvedPrivateAddressException { host, addresses ->
                                policy.permitsResolvedPrivateIpv4Exception(host, addresses.map { it.hostAddress })
                            }
                        }
                    }
        return OkHttp.create {
            config {
                sslSocketFactory(sslContext.socketFactory, trustManager)
                followRedirects(options.followRedirects && egressGuard == null)
                followSslRedirects(options.followRedirects && egressGuard == null)
                    if (egressGuard != null) {
                        dns(egressGuard.dns)
                        // A system or Wi-Fi proxy would resolve the target itself and skip the check in the resolver above, so a guarded
                        // client always connects directly.
                        proxy(java.net.Proxy.NO_PROXY)
                        addInterceptor(egressGuard.literalInterceptor)
                    }
                val versions =
                    when (sslConfig.client.minimumTlsVersion) {
                        HttpMinimumTlsVersion.TLS_1_2 -> arrayOf(TlsVersion.TLS_1_3, TlsVersion.TLS_1_2)
                        HttpMinimumTlsVersion.TLS_1_3 -> arrayOf(TlsVersion.TLS_1_3)
                    }
                connectionSpecs(
                    listOf(
                        ConnectionSpec
                            .Builder(ConnectionSpec.RESTRICTED_TLS)
                            .tlsVersions(*versions)
                            .build(),
                        // Preserve the legacy generic HTTP-client surface. Governed request
                        // contexts reject non-HTTPS destinations before this factory is called.
                        ConnectionSpec.CLEARTEXT,
                    ),
                )
            }
        }
    }

    private companion object {
        const val SHA1_HEX_LENGTH: Int = 40
    }
}
