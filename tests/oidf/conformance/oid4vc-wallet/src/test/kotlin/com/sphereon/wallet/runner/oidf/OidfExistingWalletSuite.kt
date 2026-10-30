// Copyright 2026 Sphereon International B.V. Licensed under a commercial source-available license.
package com.sphereon.wallet.runner.oidf

import com.sphereon.oidf.conformance.OidfConformanceSuiteClient
import com.sphereon.oidf.conformance.OidfSuiteConfigPreprocessor
import java.net.URI
import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyStore
import java.security.cert.CertificateFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory

/** Connects to the explicitly supplied Docker suite; wallet traffic uses its public TLS ingress. */
internal data class OidfExistingWalletSuite(
    val client: OidfConformanceSuiteClient,
    val preprocessor: OidfSuiteConfigPreprocessor,
)

internal fun existingOidfWalletSuite(): OidfExistingWalletSuite? {
    val api = System.getProperty("oidf.suite.apiBaseUrl")?.takeIf(String::isNotBlank) ?: return null

    fun required(name: String) = checkNotNull(System.getProperty(name)?.takeIf(String::isNotBlank)) { "Missing $name" }

    val protocol = oidfExistingSuiteOrigin(required("oidf.suite.protocolBaseUrl"))
    val apiOrigin = oidfExistingSuiteOrigin(api)
    val source = Path.of(required("oidf.suite.dir"))
    require(Files.isDirectory(source)) { "Missing locked OIDF source directory: $source" }
    val ca = Path.of(required("oidf.suite.caCert"))
    val certificate = Files.newInputStream(ca).use { CertificateFactory.getInstance("X.509").generateCertificate(it) }
    val keyStore =
        KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null)
            setCertificateEntry("explicit-oidf-suite-api", certificate)
        }
    val trustManagers =
        TrustManagerFactory
            .getInstance(TrustManagerFactory.getDefaultAlgorithm())
            .apply { init(keyStore) }
            .trustManagers
    val sslContext = SSLContext.getInstance("TLS").apply { init(null, trustManagers, null) }
    return OidfExistingWalletSuite(
        OidfConformanceSuiteClient(
            apiOrigin,
            sslContext = sslContext,
            originAliases = mapOf(protocol to apiOrigin),
            browserOrigin = protocol,
        ),
        OidfSuiteConfigPreprocessor(source, baseUrl = protocol, localBaseUrl = protocol),
    )
}

internal fun oidfExistingSuiteOrigin(value: String): String {
    val uri = URI.create(value)
    require(
        uri.scheme == "https" && !uri.host.isNullOrBlank() && uri.rawUserInfo == null &&
            uri.rawQuery == null && uri.rawFragment == null && uri.rawPath.orEmpty() in setOf("", "/"),
    ) {
        "OIDF suite origins must be explicit HTTPS origins without credentials, query or path"
    }
    return value.trimEnd('/')
}
