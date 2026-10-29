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

package com.sphereon.ktor.http.client.provider

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.Dns
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.Request
import okio.BufferedSource
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.URI
import java.net.UnknownHostException
import java.util.concurrent.TimeUnit
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/** Why an address is not globally routable, mapped onto the [UrlValidationPolicy] flags that gate it. */
enum class EgressAddressClass {
    PUBLIC,

    /** Loopback, unspecified, link-local, site-local, multicast, reserved, documentation and Teredo ranges. */
    PRIVATE_NETWORK,

    /** RFC 1918 and IPv6 unique-local (fc00::/7). */
    RFC1918,

    /** Carrier-grade NAT (100.64.0.0/10) and benchmarking (198.18.0.0/15). */
    SHARED,
}

/**
 * Which resolved addresses an egress connection may reach. [isPublic] allows only globally routable unicast
 * addresses: loopback, unspecified, private (RFC 1918), shared (100.64.0.0/10), link-local, unique-local (fc00::/7),
 * multicast, reserved, benchmarking and documentation ranges are refused, and the IPv4 address embedded in an
 * IPv4-mapped, NAT64 or 6to4 IPv6 address is checked as an IPv4 address. [isAllowed] applies the same
 * classification to the individual block flags of a [UrlValidationPolicy].
 */
object EgressAddressPolicy {
    fun isPublic(address: InetAddress): Boolean = classify(address) == EgressAddressClass.PUBLIC

    /** True when the [policy] does not block the class this address falls into. */
    fun isAllowed(
        address: InetAddress,
        policy: UrlValidationPolicy,
    ): Boolean =
        when (classify(address)) {
            EgressAddressClass.PUBLIC -> true
            EgressAddressClass.PRIVATE_NETWORK -> !policy.blockPrivateNetworks
            EgressAddressClass.RFC1918 -> !policy.blockRfc1918
            EgressAddressClass.SHARED -> !policy.blockSharedNetworks
        }

    fun classify(address: InetAddress): EgressAddressClass =
        when (address) {
            is Inet4Address -> classifyV4(address.address)
            is Inet6Address -> classifyV6(address.address)
            else -> EgressAddressClass.PRIVATE_NETWORK
        }

    private fun classifyV4(b: ByteArray): EgressAddressClass {
        val a = b[0].toInt() and 0xFF
        val c = b[1].toInt() and 0xFF
        val third = b[2].toInt() and 0xFF
        return when {
            a == 0 -> EgressAddressClass.PRIVATE_NETWORK
            a == 10 -> EgressAddressClass.RFC1918
            a == 127 -> EgressAddressClass.PRIVATE_NETWORK
            a == 100 && c in 64..127 -> EgressAddressClass.SHARED
            a == 169 && c == 254 -> EgressAddressClass.PRIVATE_NETWORK
            a == 172 && c in 16..31 -> EgressAddressClass.RFC1918
            a == 192 && c == 0 && third == 0 -> EgressAddressClass.PRIVATE_NETWORK
            a == 192 && c == 0 && third == 2 -> EgressAddressClass.PRIVATE_NETWORK
            a == 192 && c == 168 -> EgressAddressClass.RFC1918
            a == 192 && c == 88 && third == 99 -> EgressAddressClass.PRIVATE_NETWORK
            a == 198 && c in 18..19 -> EgressAddressClass.SHARED
            a == 198 && c == 51 && third == 100 -> EgressAddressClass.PRIVATE_NETWORK
            a == 203 && c == 0 && third == 113 -> EgressAddressClass.PRIVATE_NETWORK
            a >= 224 -> EgressAddressClass.PRIVATE_NETWORK
            else -> EgressAddressClass.PUBLIC
        }
    }

    private fun classifyV6(b: ByteArray): EgressAddressClass {
        fun at(i: Int) = b[i].toInt() and 0xFF
        if (b.all { it == 0.toByte() }) return EgressAddressClass.PRIVATE_NETWORK
        if ((0..14).all { b[it] == 0.toByte() } && at(15) == 1) return EgressAddressClass.PRIVATE_NETWORK
        val first = at(0)
        val second = at(1)
        if (first == 0xFF) return EgressAddressClass.PRIVATE_NETWORK
        if ((first and 0xFE) == 0xFC) return EgressAddressClass.RFC1918
        if (first == 0xFE && (second and 0xC0) == 0x80) return EgressAddressClass.PRIVATE_NETWORK
        if (first == 0xFE && (second and 0xC0) == 0xC0) return EgressAddressClass.PRIVATE_NETWORK
        // IPv4-mapped (::ffff:a.b.c.d) and IPv4-compatible (::a.b.c.d)
        if ((0..9).all { b[it] == 0.toByte() } && ((at(10) == 0xFF && at(11) == 0xFF) || (at(10) == 0 && at(11) == 0))) {
            return classifyV4(b.copyOfRange(12, 16))
        }
        // IPv4-translated (::ffff:0:a.b.c.d) embeds an IPv4 address like the mapped form does
        if ((0..7).all { b[it] == 0.toByte() } && at(8) == 0xFF && at(9) == 0xFF && at(10) == 0 && at(11) == 0) {
            return classifyV4(b.copyOfRange(12, 16))
        }
        // 64:ff9b:1::/48 is the local-use NAT64 prefix (RFC 8215): the local network chooses what it maps
        if (at(0) == 0x00 && at(1) == 0x64 && at(2) == 0xFF && at(3) == 0x9B && at(4) == 0x00 && at(5) == 0x01) {
            return EgressAddressClass.PRIVATE_NETWORK
        }
        // NAT64 well-known prefix 64:ff9b::/96 embeds an IPv4 address
        if (at(0) == 0x00 && at(1) == 0x64 && at(2) == 0xFF && at(3) == 0x9B && (4..11).all { b[it] == 0.toByte() }) {
            return classifyV4(b.copyOfRange(12, 16))
        }
        // 6to4 (2002::/16) embeds the IPv4 address in bytes 2..5
        if (at(0) == 0x20 && at(1) == 0x02) return classifyV4(b.copyOfRange(2, 6))
        // Teredo (2001::/32) and documentation (2001:db8::/32)
        if (at(0) == 0x20 && at(1) == 0x01 && at(2) == 0x00 && at(3) == 0x00) return EgressAddressClass.PRIVATE_NETWORK
        if (at(0) == 0x20 && at(1) == 0x01 && at(2) == 0x0D && at(3) == 0xB8) return EgressAddressClass.PRIVATE_NETWORK
        return EgressAddressClass.PUBLIC
    }
}

/** Raised from inside the connection's DNS lookup when a host resolves to an address the egress policy refuses. */
class BlockedEgressAddressException(
    message: String,
) : UnknownHostException(message),
    EgressRefusal

/**
 * The single resolved-address guard shared by every JVM HTTP client that must not reach internal addresses
 * ([HttpClientFactoryJvmImpl] for policies that block address ranges, and [ValidatedEgressHttpFetcher]).
 *
 * The check sits inside the resolver the connection uses ([dns]), so a DNS rebinding answer cannot slip in between
 * check and connect, and the connection is made to exactly the validated addresses. OkHttp does not consult the
 * resolver for IP literals, so [literalInterceptor] validates a literal host of every request the engine sends
 * (including each redirect hop that reaches the engine).
 */
class EgressGuard(
    private val addressPolicy: (InetAddress) -> Boolean,
    private val resolver: (String) -> List<InetAddress> = { host -> InetAddress.getAllByName(host).toList() },
) {
    private var resolvedPrivateAddressException: ((String, List<InetAddress>) -> Boolean?)? = null

    /** Install an exact private-address exception check before exposing this guard to a client engine. */
    fun installResolvedPrivateAddressException(policy: (String, List<InetAddress>) -> Boolean?) {
        check(resolvedPrivateAddressException == null) { "A resolved private-address exception is already installed" }
        resolvedPrivateAddressException = policy
    }

    val dns: Dns =
        object : Dns {
            override fun lookup(hostname: String): List<InetAddress> = resolveValidated(hostname)
        }

    /** Application interceptor: refuses a request whose host is an IP literal the policy does not allow. */
    val literalInterceptor: Interceptor =
        Interceptor { chain ->
            val host = chain.request().url.host
            if (looksLikeIpLiteral(host)) resolveValidated(host)
            chain.proceed(chain.request())
        }

    /** Resolves [host] and returns its addresses, or throws [UnknownHostException] when any address is refused. */
    fun resolveValidated(host: String): List<InetAddress> {
        val bare = host.removePrefix("[").removeSuffix("]")
        val addresses =
            try {
                resolver(bare)
            } catch (_: Exception) {
                throw UnknownHostException("The host could not be resolved")
            }
        if (addresses.isEmpty()) throw UnknownHostException("The host could not be resolved")
        val exceptionResult =
            resolvedPrivateAddressException?.let { policy ->
                runCatching { policy(bare.lowercase().removeSuffix("."), addresses) }.getOrDefault(false)
            }
        val allowed = exceptionResult ?: addresses.all(addressPolicy)
        if (!allowed) throw BlockedEgressAddressException("The host resolves to an address that is not allowed")
        return addresses
    }

    private fun looksLikeIpLiteral(host: String): Boolean = host.contains(':') || host.all { it.isDigit() || it == '.' }
}

/** Failure of a validated egress fetch. The message never carries a response body. */
class EgressFetchException(
    message: String,
) : IOException(message)

class EgressFetchResponse(
    val url: String,
    val status: Int,
    val contentType: String?,
    val bytes: ByteArray,
)

/**
 * Fetches a URL with the SSRF defences that a fetch of an attacker-influenced URL needs, independent of the platform
 * HTTP client defaults:
 *
 * - `https` only (configurable for tests), no userinfo, and only the allowed ports;
 * - every address the host resolves to is validated by the address policy, and the connection is made to exactly
 *   those validated addresses: the check sits inside the resolver the connection uses, so a DNS rebinding answer
 *   cannot slip in between check and connect;
 * - IP literals are validated the same way;
 * - redirects are never followed;
 * - the body is read as a stream and refused as soon as it exceeds the byte cap, whatever `Content-Length` says;
 * - the whole request is bounded by the request timeout;
 * - failure messages contain the status code or a fixed reason, never response content.
 *
 * @param allowedPorts ports that may be contacted, or null for any port.
 */
class ValidatedEgressHttpFetcher(
    private val maxBytes: Long,
    private val requestTimeout: Duration = 30.seconds,
    private val allowedPorts: Set<Int>? = setOf(443),
    private val allowedSchemes: Set<String> = setOf("https"),
    private val addressPolicy: (InetAddress) -> Boolean = EgressAddressPolicy::isPublic,
    private val resolver: (String) -> List<InetAddress> = { host -> InetAddress.getAllByName(host).toList() },
) {
    private val guard = EgressGuard(addressPolicy, resolver)

    private val client: OkHttpClient =
        OkHttpClient
            .Builder()
            .dns(guard.dns)
            .proxy(java.net.Proxy.NO_PROXY)
            .addInterceptor(guard.literalInterceptor)
            .followRedirects(false)
            .followSslRedirects(false)
            .retryOnConnectionFailure(false)
            .connectTimeout(requestTimeout.inWholeMilliseconds, TimeUnit.MILLISECONDS)
            .readTimeout(requestTimeout.inWholeMilliseconds, TimeUnit.MILLISECONDS)
            .callTimeout(requestTimeout.inWholeMilliseconds, TimeUnit.MILLISECONDS)
            .build()

    /** Throws [EgressFetchException] when the URL may not be fetched. Resolves the host, so a name that maps to a private address is refused. */
    fun validate(url: String) {
        val uri =
            try {
                URI(url)
            } catch (_: Exception) {
                throw EgressFetchException("The URL is not valid")
            }
        val scheme = uri.scheme?.lowercase()
        if (scheme == null || scheme !in allowedSchemes) throw EgressFetchException("Only ${allowedSchemes.joinToString(" and ")} URLs can be fetched")
        if (uri.userInfo != null) throw EgressFetchException("URLs with userinfo are not allowed")
        val host = uri.host?.takeIf { it.isNotBlank() } ?: throw EgressFetchException("The URL has no host")
        val port = if (uri.port == -1) (if (scheme == "https") 443 else 80) else uri.port
        if (allowedPorts != null && port !in allowedPorts) throw EgressFetchException("Port $port is not allowed")
        try {
            guard.resolveValidated(host)
        } catch (_: UnknownHostException) {
            throw EgressFetchException("The host could not be resolved or is not allowed")
        }
    }

    suspend fun get(
        url: String,
        headers: Map<String, String> = emptyMap(),
    ): EgressFetchResponse {
        validate(url)
        return withContext(Dispatchers.IO) {
            val request =
                try {
                    Request
                        .Builder()
                        .url(url)
                        .apply { headers.forEach { (name, value) -> header(name, value) } }
                        .get()
                        .build()
                } catch (_: Exception) {
                    throw EgressFetchException("The URL is not valid")
                }
            try {
                client.newCall(request).execute().use { response ->
                    if (response.code !in 200..299) throw EgressFetchException("HTTP ${response.code}")
                    val body = checkNotNull(response.body)
                    val declared = body.contentLength()
                    if (declared > maxBytes) throw EgressFetchException("The response exceeds the $maxBytes byte limit")
                    EgressFetchResponse(url, response.code, response.header("Content-Type"), readCapped(body.source()))
                }
            } catch (e: EgressFetchException) {
                throw e
            } catch (_: UnknownHostException) {
                throw EgressFetchException("The host could not be resolved or is not allowed")
            } catch (_: Exception) {
                throw EgressFetchException("The request failed")
            }
        }
    }

    private fun readCapped(source: BufferedSource): ByteArray {
        val out = ByteArrayOutputStream()
        val buffer = ByteArray(8192)
        var total = 0L
        while (true) {
            val read = source.read(buffer)
            if (read < 0) break
            total += read
            if (total > maxBytes) throw EgressFetchException("The response exceeds the $maxBytes byte limit")
            out.write(buffer, 0, read)
        }
        return out.toByteArray()
    }
}
