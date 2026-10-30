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

import com.sphereon.core.api.conf.ConfigLevel
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.crypto.core.kms.HasKeyStoreService
import com.sphereon.crypto.core.kms.KeyManagerService
import com.sphereon.crypto.core.kms.KeyStoreManager
import com.sphereon.crypto.kms.keystore.software.SoftwareKeyStoreService
import com.sphereon.di.session.SessionScope
import com.sphereon.ktor.http.client.config.CaOpts
import com.sphereon.ktor.http.client.config.SslConfig
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.Provider
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
import javax.net.ssl.X509KeyManager
import javax.net.ssl.X509TrustManager
import kotlinx.coroutines.runBlocking
import okhttp3.ConnectionSpec
import okhttp3.TlsVersion

/**
 * KMS-backed JVM HTTP client factory (mTLS + keystore CAs + PEM trust).
 *
 * Higher [HttpClientBindingPriority.KMS] wins over the default crypto-free factory when this
 * module is on the classpath.
 */
@Inject
@SingleIn(SessionScope::class)
@ContributesBinding(SessionScope::class, priority = HttpClientBindingPriority.KMS)
class HttpClientFactoryJvmKmsImpl(
    private val execution: SessionExecution,
    private val kms: Provider<KeyManagerService>,
    private val keyStoreManager: Provider<KeyStoreManager>,
) : HttpClientFactory {
    val keyStores: MutableSet<com.sphereon.crypto.core.kms.KeyStore> = mutableSetOf()

    private var configuredKeyStoresLoaded = false
    private var providerKeyStoresLoaded = false

    private val log = execution.log.logManager.withTag("HttpClientFactoryKms")

    internal var egressResolver: (String) -> List<InetAddress> = { host -> InetAddress.getAllByName(host).toList() }

    override fun createClient(options: HttpClientOptions): HttpClient {
        require(isSupportedOptions(options)) { "Provided http client options are not supported on this platform" }

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

    private suspend fun buildTrustManagers(caOpts: CaOpts): Set<X509TrustManager> {
        if (caOpts.includePlatformDefaults && !caOpts.hasCustomTrust()) {
            val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            tmf.init(null as KeyStore?)
            return tmf.trustManagers.filterIsInstance<X509TrustManager>().toSet()
        }

        if (caOpts.additionalCAs.isNotEmpty()) {
            addConfiguredKeystores()
            addProviderKeystores()
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

        for (ca in caOpts.additionalCAs) {
            val keyStore = getSupportedKeyStore(ca.keyStoreId).platformKeyStore
            val cert = keyStore.getCertificate(ca.certificateAlias) ?: error("Certificate alias ${ca.certificateAlias} not found in ${ca.keyStoreId}")
            trustStore.setCertificateEntry(ca.certificateAlias, cert)
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

    private fun getSupportedKeyStore(id: String): SoftwareKeyStoreService {
        val keyStore = keyStores.firstOrNull { it.id == id } ?: throw IllegalArgumentException("Keystore $id not found. Available: ${keyStores.joinToString(",") { it.id }}}")
        require(keyStore is SoftwareKeyStoreService) { "Only Software keystores can be used for SSL client certificates. Keystore $id was of type ${keyStore::class.simpleName}" }
        return keyStore
    }

    private suspend fun buildClientSslContext(
        sslConfig: SslConfig,
        trustManagers: Set<X509TrustManager>? = null,
    ): SSLContext {
        val clientKeyStoreIds = sslConfig.client.allKeyStoreIds()
        if (clientKeyStoreIds.isNotEmpty()) {
            addConfiguredKeystores()
            addProviderKeystores()
        }
        val keyManagers = mutableSetOf<X509KeyManager>()
        for (id in clientKeyStoreIds) {
            val keyStore = getSupportedKeyStore(id)
            keyManagers.addAll(keyStore.platformKeyManagerFactory.keyManagers.filterIsInstance<X509KeyManager>())
        }
        val compositeKeyManager = CompositeKeyManager(keyManagers)
        val hostBasedKeyManager =
            HostBasedKeyManager(delegate = compositeKeyManager, hostNameToAlias = sslConfig.client.hostNameToAlias(), defaultAlias = sslConfig.client.defaultAlias())

        val tms = trustManagers ?: buildTrustManagers(sslConfig.server.ca)
        return SSLContext.getInstance("TLS").apply { init(arrayOf(hostBasedKeyManager), tms.toTypedArray(), null) }
    }

    private fun createOkHttpEngine(options: HttpClientOptions): HttpClientEngine =
        runBlocking {
            val sslConfig = options.sslConfig
            val trustManagers = buildTrustManagers(sslConfig.server.ca)
            val sslContext = buildClientSslContext(sslConfig, trustManagers)
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
            OkHttp.create {
                config {
                    sslSocketFactory(sslContext.socketFactory, CompositeTrustManager(trustManagers))
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
                            ConnectionSpec.CLEARTEXT,
                        ),
                    )
                }
            }
        }

    private fun addConfiguredKeystores() {
        if (configuredKeyStoresLoaded) return
        configuredKeyStoresLoaded = true
        val manager = keyStoreManager()
        keyStores.addAll(manager.createFromProperties(execution.conf.conf(ConfigLevel.APP)))
        keyStores.addAll(manager.createFromProperties(execution.conf.conf(ConfigLevel.TENANT)))
        keyStores.addAll(manager.createFromProperties(execution.conf.conf(ConfigLevel.PRINCIPAL)))
    }

    private companion object {
        const val SHA1_HEX_LENGTH: Int = 40
    }

    private suspend fun addProviderKeystores() {
        if (providerKeyStoresLoaded) return
        providerKeyStoresLoaded = true
        val manager = kms()
        for (providerId in manager.getProviderIds()) {
            val provider = manager.getProviderById(providerId)
            if (provider is HasKeyStoreService && provider.keyStore is SoftwareKeyStoreService) {
                keyStores.add(provider.keyStore as SoftwareKeyStoreService)
            }
        }
    }
}
