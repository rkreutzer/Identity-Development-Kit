/*
 * Copyright 2023-2026 Sphereon International B.V.
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

import com.sphereon.core.compat.JsExportCompat
import io.ktor.http.Url

private val COUNTERPARTY_BLOCKED_HOSTS = setOf(
    "localhost",
    "metadata.google.internal",
    "metadata.azure.internal",
    "instance-data.ec2.internal",
)
private val COUNTERPARTY_BLOCKED_HOST_SUFFIXES = setOf(
    ".local",
    ".internal",
    ".localhost",
    ".corp",
    ".home.arpa",
)

/**
 * Policy for validating request URLs before they are sent.
 *
 * Install via [HttpClientOptions.urlValidation] to enforce SSRF protection
 * at the HTTP client infrastructure level, rather than in individual consumers.
 *
 * When a request URL violates the policy, the client throws [UrlValidationException]
 * before the request is sent.
 *
 * The address flags ([blockPrivateNetworks], [blockRfc1918], [blockSharedNetworks]) are enforced in two places.
 * [validate] checks the literal host of a URL, on every platform. On the JVM the [HttpClientFactory] additionally
 * checks every address a host name RESOLVES to, inside the connection's own DNS lookup, so a name that maps to a
 * loopback, private, link-local or metadata address, and a DNS rebinding answer, is refused at connect time. Every
 * redirect hop is validated the same way before it is followed. The other targets (JS, wasmJs, Apple, Linux) do not
 * expose the engine's resolver, so they only get the literal-host check; do not rely on those targets to stop a
 * host name that resolves to an internal address. Use [ALLOW_PRIVATE] (or [NONE]) for clients that must reach
 * internal services.
 */
@JsExportCompat
data class UrlValidationPolicy(
    /** Allow only these schemes (e.g., "https", "http"). Empty = all allowed. */
    val allowedSchemes: Set<String> = setOf("https", "http"),
    /** Block URLs containing userinfo (user:pass@host). Prevents auth-based SSRF bypasses. */
    val blockUserInfo: Boolean = true,
    /** Block requests to private/internal network addresses (loopback, link-local, metadata endpoints). */
    val blockPrivateNetworks: Boolean = true,
    /** Block RFC 1918 private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16). */
    val blockRfc1918: Boolean = true,
    /** Block carrier-grade NAT (100.64.0.0/10) and benchmark (198.18.0.0/15) ranges. */
    val blockSharedNetworks: Boolean = true,
    /** Additional hostnames to block (exact match, lowercase). */
    val blockedHosts: Set<String> = emptySet(),
    /** Additional hostname suffixes to block (e.g., ".internal", ".local"). */
    val blockedHostSuffixes: Set<String> = emptySet(),
    /** Optional execution-scoped destination that every request must match canonically. */
    val exactTargetUri: String? = null,
    /**
     * Refuse to build a client on a platform whose engine cannot check the addresses it actually connects to. The
     * literal-host check of [validate] cannot stop a host name that resolves to an internal address, so a policy that
     * must hold ([COUNTERPARTY_EGRESS]) sets this and the JS, wasmJs, Apple and Linux factories fail closed.
     */
    val requireResolvedAddressEnforcement: Boolean = false,
    /** Exact HTTPS DNS authorities and RFC 1918 IPv4 answers explicitly permitted by an operator. */
    val resolvedPrivateIpv4Targets: Set<ResolvedPrivateIpv4Target> = emptySet(),
) {
    init {
        require(resolvedPrivateIpv4Targets.map { it.host }.distinct().size == resolvedPrivateIpv4Targets.size) {
            "only one private IPv4 target entry may be configured per hostname"
        }
        require(
            resolvedPrivateIpv4Targets.isEmpty() ||
                (
                    allowedSchemes == setOf("https") && blockUserInfo && blockPrivateNetworks && blockRfc1918 &&
                        blockSharedNetworks && requireResolvedAddressEnforcement &&
                        blockedHosts.containsAll(COUNTERPARTY_BLOCKED_HOSTS) &&
                        blockedHostSuffixes.containsAll(COUNTERPARTY_BLOCKED_HOST_SUFFIXES)
                ),
        ) {
            "private IPv4 targets require the strict HTTPS counterparty policy"
        }
    }

    /**
     * Refuses a numeric address, as printed by an engine's resolver, that the address flags of this policy block. Platform
     * engines that resolve a host themselves call this for every address a host name resolves to. The message names no
     * address.
     */
    fun validateResolvedAddress(address: String) {
        if (checkIpRanges(address, blockPrivateNetworks, blockRfc1918, blockSharedNetworks) != null) {
            throw UrlValidationException("The host resolves to an address that is not allowed")
        }
    }

    /**
     * Validate the complete answer set returned by the JVM resolver. An exact configured authority is permitted
     * only when every DNS answer is one of its explicitly configured RFC 1918 IPv4 addresses. This rejects mixed,
     * changed, and rebound answers while allowing the engine to connect to the same validated set.
     */
    fun permitsResolvedPrivateIpv4Exception(host: String, addresses: List<String>): Boolean? {
        val normalizedHost = host.lowercase().removeSuffix(".")
        val target = resolvedPrivateIpv4Targets.singleOrNull { it.host == normalizedHost }
            ?: return null
        return addresses.isNotEmpty() && addresses.all { isCanonicalRfc1918Ipv4(it) && it in target.addresses }
    }

    /**
     * Validate a URL against this policy.
     * @throws UrlValidationException if the URL violates the policy.
     */
    fun validate(url: Url) {
        // Scheme check
        if (allowedSchemes.isNotEmpty() && url.protocol.name.lowercase() !in allowedSchemes) {
            throw UrlValidationException("Scheme '${url.protocol.name}' is not allowed. Allowed: $allowedSchemes")
        }

        // Userinfo check
        if (blockUserInfo && (url.user != null || url.password != null)) {
            throw UrlValidationException("URLs with userinfo are not allowed")
        }

        exactTargetUri?.let { approvedUri ->
            validateExactTarget(approved = Url(approvedUri), requested = url)
        }

        val rawHost = url.host.lowercase()
        val host = rawHost.trimEnd('.')
        if (host.isEmpty()) {
            throw UrlValidationException("URL has no host")
        }

        // Exact host block
        if (host in blockedHosts) {
            throw UrlValidationException("Host '$host' is blocked")
        }

        // Suffix block
        for (suffix in blockedHostSuffixes) {
            if (host.endsWith(suffix)) {
                throw UrlValidationException("Host '$host' is blocked (suffix: $suffix)")
            }
        }

        resolvedPrivateIpv4Targets.singleOrNull { it.host == host }?.let { target ->
            if (rawHost != host || url.port != target.port) {
                throw UrlValidationException("The private-address exception does not match this HTTPS authority")
            }
        }

        // Network range checks (pass policy flags)
        val ipCheckResult = checkIpRanges(host, blockPrivateNetworks, blockRfc1918, blockSharedNetworks)
        if (ipCheckResult != null) {
            throw UrlValidationException(ipCheckResult)
        }
    }

    companion object {
        /** No URL validation â€” allows all requests. */
        val NONE =
            UrlValidationPolicy(
                allowedSchemes = emptySet(),
                blockUserInfo = false,
                blockPrivateNetworks = false,
                blockRfc1918 = false,
                blockSharedNetworks = false,
            )

        /** Standard SSRF protection for external-facing HTTP clients. */
        val BLOCK_PRIVATE =
            UrlValidationPolicy(
                allowedSchemes = setOf("https", "http"),
                blockUserInfo = true,
                blockPrivateNetworks = true,
                blockRfc1918 = true,
                blockSharedNetworks = true,
                blockedHosts =
                    setOf(
                        "localhost",
                        "127.0.0.1",
                        "::1",
                        "0.0.0.0",
                        "metadata.google.internal",
                        "169.254.169.254",
                    ),
                blockedHostSuffixes =
                    setOf(
                        ".local",
                        ".internal",
                        ".localhost",
                        ".corp",
                        ".home.arpa",
                    ),
            )

        /**
         * The egress rule for every fetch a wallet holder makes on a counterparty-supplied URL (request_uri,
         * client metadata, credential offer, issuer and authorization server metadata, token, credential, nonce and
         * notification endpoints, JWKS, status lists, did:web documents). There is no variant that allows internal
         * destinations: https only, no userinfo, and loopback, private, shared, link-local, multicast and reserved
         * addresses are refused both as literals and, on the JVM, as the addresses the connection resolves to
         * (including every redirect hop). Platforms that cannot check resolved addresses fail closed
         * ([requireResolvedAddressEnforcement]).
         */
        val COUNTERPARTY_EGRESS =
            UrlValidationPolicy(
                allowedSchemes = setOf("https"),
                blockUserInfo = true,
                blockPrivateNetworks = true,
                blockRfc1918 = true,
                blockSharedNetworks = true,
                blockedHosts =
                    COUNTERPARTY_BLOCKED_HOSTS,
                blockedHostSuffixes = COUNTERPARTY_BLOCKED_HOST_SUFFIXES,
                requireResolvedAddressEnforcement = true,
            )

        /**
         * Explicit opt-in for clients that legitimately reach internal services (local development, compose or cluster
         * east-west calls, an in-network authorization server): loopback, RFC 1918 and shared ranges are allowed, both as
         * literals and as resolved addresses. Userinfo is still refused and cloud metadata endpoints stay blocked by name.
         */
        val ALLOW_PRIVATE =
            UrlValidationPolicy(
                allowedSchemes = setOf("https", "http"),
                blockUserInfo = true,
                blockPrivateNetworks = false,
                blockRfc1918 = false,
                blockSharedNetworks = false,
                blockedHosts =
                    setOf(
                        "metadata.google.internal",
                        "metadata.azure.internal",
                        "instance-data.ec2.internal",
                        "169.254.169.254",
                    ),
            )

        /** Exact HTTPS destination guard for one already-approved governed request context. */
        fun exactTarget(destinationUri: String): UrlValidationPolicy {
            val destination = Url(destinationUri)
            if (!destination.protocol.name.equals("https", ignoreCase = true)) {
                throw UrlValidationException("Governed exact targets require HTTPS")
            }
            requireNoAuthorityCredentialsOrFragment(destination)
            return UrlValidationPolicy(
                allowedSchemes = setOf("https"),
                blockUserInfo = true,
                blockPrivateNetworks = false,
                blockRfc1918 = false,
                blockSharedNetworks = false,
                exactTargetUri = destinationUri,
            )
        }
    }
}

/** One exact DNS hostname/port paired with its operator-approved RFC 1918 IPv4 addresses. */
@JsExportCompat
data class ResolvedPrivateIpv4Target(
    val host: String,
    val port: Int,
    val addresses: Set<String>,
) {
    init {
        require(isCanonicalDnsTargetHost(host)) { "private IPv4 targets require a canonical DNS hostname" }
        require(port in 1..65535) { "private IPv4 target port is out of range" }
        require(addresses.isNotEmpty()) { "private IPv4 target must contain at least one address" }
        require(addresses.all(::isCanonicalRfc1918Ipv4)) { "private IPv4 target addresses must be canonical RFC 1918 IPv4 literals" }
    }
}

private fun isCanonicalDnsTargetHost(host: String): Boolean {
    if (host != host.lowercase() || host.endsWith('.') || host.length !in 1..253 || !host.contains('.')) return false
    if (parseIpv4Literal(host) != null || parseIpv6Literal(host) != null) return false
    if (host == "localhost" || host.endsWith(".localhost") || host.endsWith(".local") ||
        host.endsWith(".internal") || host.endsWith(".corp") || host.endsWith(".home.arpa")
    ) return false
    val labels = host.split('.')
    return labels.all { label ->
        fun asciiAlphaNumeric(char: Char) = char in 'a'..'z' || char in '0'..'9'
        label.length in 1..63 && asciiAlphaNumeric(label.first()) && asciiAlphaNumeric(label.last()) &&
            label.all { asciiAlphaNumeric(it) || it == '-' }
    }
}

private fun isCanonicalRfc1918Ipv4(address: String): Boolean {
    val pieces = address.split('.')
    if (pieces.size != 4) return false
    val octets = IntArray(4)
    for (index in pieces.indices) {
        val piece = pieces[index]
        if (piece.isEmpty() || piece.any { !it.isDigit() } || (piece.length > 1 && piece.startsWith('0'))) return false
        val value = piece.toIntOrNull() ?: return false
        if (value !in 0..255) return false
        octets[index] = value
    }
    return octets[0] == 10 ||
        (octets[0] == 172 && octets[1] in 16..31) ||
        (octets[0] == 192 && octets[1] == 168)
}

private data class CanonicalUrlTarget(
    val scheme: String,
    val host: String,
    val effectivePort: Int,
    val encodedPath: String,
    val query: List<Pair<String, List<String>>>,
)

private fun validateExactTarget(approved: Url, requested: Url) {
    requireNoAuthorityCredentialsOrFragment(approved)
    requireNoAuthorityCredentialsOrFragment(requested)
    if (approved.canonicalTarget() != requested.canonicalTarget()) {
        throw UrlValidationException("Request URL does not match the approved governed destination")
    }
}

private fun requireNoAuthorityCredentialsOrFragment(url: Url) {
    if (url.user != null || url.password != null) {
        throw UrlValidationException("Governed request targets must not contain userinfo")
    }
    if (url.fragment.isNotEmpty()) {
        throw UrlValidationException("Governed request targets must not contain fragments")
    }
}

private fun Url.canonicalTarget(): CanonicalUrlTarget =
    CanonicalUrlTarget(
        scheme = protocol.name.lowercase(),
        host = host.trim().trimEnd('.').lowercase(),
        effectivePort = port,
        encodedPath = encodedPath,
        query = parameters.names().sorted().map { name -> name to parameters.getAll(name).orEmpty() },
    )

/**
 * Thrown when a request URL violates the configured [UrlValidationPolicy].
 */
@JsExportCompat
class UrlValidationException(
    message: String,
) : IllegalArgumentException(message)

/**
 * Check whether a hostname falls in blocked IP ranges.
 * Returns an error message if blocked, null if allowed.
 *
 * Handles IPv4 (including octal/hex-encoded octets and a single decimal or hex integer), IPv6 in every textual
 * form (compressed, with a dotted tail, with a zone id), and the IPv4 address embedded in an IPv4-mapped
 * (::ffff:a.b.c.d), IPv4-compatible (::a.b.c.d), NAT64 (64:ff9b::/96) or 6to4 (2002::/16) address. The
 * `blockPrivateNetworks` flag covers 0/8, 127/8, 169.254/16, 192.0.0/24, 224/4 and above, `::`, `::1`, fe80::/10,
 * fec0::/10, fc00::/7 and ff00::/8.
 */
internal fun checkIpRanges(
    host: String,
    blockPrivateNetworks: Boolean,
    blockRfc1918: Boolean,
    blockSharedNetworks: Boolean,
): String? {
    val bare = host.removeSurrounding("[", "]")
    val v6 = parseIpv6Literal(bare)
    if (v6 != null) return checkIpv6Bytes(v6, host, blockPrivateNetworks, blockRfc1918, blockSharedNetworks)
    val v4 = parseIpv4Literal(bare) ?: return null
    return checkIpv4Octets(v4, host, blockPrivateNetworks, blockRfc1918, blockSharedNetworks)
}

private fun checkIpv4Octets(
    octets: IntArray,
    host: String,
    blockPrivateNetworks: Boolean,
    blockRfc1918: Boolean,
    blockSharedNetworks: Boolean,
): String? {
    val a = octets[0]
    val b = octets[1]
    val c = octets[2]

    if (blockPrivateNetworks) {
        if (a == IP_LOOPBACK) {
            return "Host '$host' is in loopback range (127.0.0.0/8)"
        }
        if (a == 0) {
            return "Host '$host' is in reserved range (0.0.0.0/8)"
        }
        if (a == IP_LINK_LOCAL_A && b == IP_LINK_LOCAL_B) {
            return "Host '$host' is in link-local range (169.254.0.0/16)"
        }
        if (a == IP_PRIVATE_CLASS_C && b == 0 && c == 0) {
            return "Host '$host' is in the IETF protocol assignment range (192.0.0.0/24)"
        }
        if (a >= IP_MULTICAST_A) {
            return "Host '$host' is in multicast or reserved range (224.0.0.0/4 and above)"
        }
    }

    if (blockRfc1918) {
        if (a == IP_PRIVATE_CLASS_A) {
            return "Host '$host' is in private range (10.0.0.0/8)"
        }
        if (a == IP_PRIVATE_CLASS_B && b in IP_PRIVATE_B_RANGE) {
            return "Host '$host' is in private range (172.16.0.0/12)"
        }
        if (a == IP_PRIVATE_CLASS_C && b == IP_PRIVATE_C_SUBNET) {
            return "Host '$host' is in private range (192.168.0.0/16)"
        }
    }

    if (blockSharedNetworks) {
        if (a == IP_CGNAT_A && b in IP_CGNAT_B_RANGE) {
            return "Host '$host' is in carrier-grade NAT range (100.64.0.0/10)"
        }
        if (a == IP_BENCHMARK_A && b in IP_BENCHMARK_B_RANGE) {
            return "Host '$host' is in benchmark range (198.18.0.0/15)"
        }
    }
    return null
}

private fun checkIpv6Bytes(
    bytes: ByteArray,
    host: String,
    blockPrivateNetworks: Boolean,
    blockRfc1918: Boolean,
    blockSharedNetworks: Boolean,
): String? {
    fun at(index: Int): Int = bytes[index].toInt() and BYTE_MASK

    fun embedded(offset: Int): String? =
        checkIpv4Octets(
            intArrayOf(at(offset), at(offset + 1), at(offset + 2), at(offset + 3)),
            host,
            blockPrivateNetworks,
            blockRfc1918,
            blockSharedNetworks,
        )

    val leadingZeroBytes = (0 until IPV6_PREFIX_BYTES).all { at(it) == 0 }
    val mapped =
        (0 until IPV6_MAPPED_ZERO_BYTES).all { at(it) == 0 } &&
            at(IPV6_MAPPED_ZERO_BYTES) == BYTE_MASK &&
            at(IPV6_MAPPED_ZERO_BYTES + 1) == BYTE_MASK
    val nat64 =
        at(0) == 0x00 && at(1) == 0x64 && at(2) == 0xFF && at(3) == 0x9B &&
            (IPV6_NAT64_ZERO_FROM until IPV6_PREFIX_BYTES).all { at(it) == 0 }
    // 64:ff9b:1::/48 is the local-use NAT64 prefix (RFC 8215): it maps addresses the local network chooses.
    val localUseNat64 = at(0) == 0x00 && at(1) == 0x64 && at(2) == 0xFF && at(3) == 0x9B && at(4) == 0x00 && at(5) == 0x01
    // ::ffff:0:a.b.c.d (IPv4-translated, RFC 2765) embeds an IPv4 address like ::ffff:a.b.c.d does.
    val translated =
        (0 until IPV6_TRANSLATED_ZERO_BYTES).all { at(it) == 0 } &&
            at(IPV6_TRANSLATED_ZERO_BYTES) == BYTE_MASK && at(IPV6_TRANSLATED_ZERO_BYTES + 1) == BYTE_MASK &&
            at(IPV6_MAPPED_ZERO_BYTES) == 0 && at(IPV6_MAPPED_ZERO_BYTES + 1) == 0

    if (blockPrivateNetworks) {
        if (leadingZeroBytes && at(IPV6_LAST_BYTE - 2) == 0 && at(IPV6_LAST_BYTE - 1) == 0 && at(IPV6_LAST_BYTE) <= 1) {
            return "Host '$host' is the IPv6 unspecified or loopback address"
        }
        if (at(0) == 0xFE && (at(1) and 0xC0) == 0x80) {
            return "Host '$host' is IPv6 link-local"
        }
        if (at(0) == 0xFE && (at(1) and 0xC0) == 0xC0) {
            return "Host '$host' is IPv6 site-local"
        }
        if (at(0) == 0xFF) {
            return "Host '$host' is IPv6 multicast"
        }
        if (localUseNat64) {
            return "Host '$host' is in the local-use NAT64 range (64:ff9b:1::/48)"
        }
        if ((at(0) and 0xFE) == 0xFC) {
            return "Host '$host' is IPv6 unique-local"
        }
    }

    // The IPv4 address an IPv6 address embeds is held to the IPv4 rules.
    if (mapped || leadingZeroBytes || nat64 || translated) return embedded(IPV6_PREFIX_BYTES)
    if (at(0) == 0x20 && at(1) == 0x02) return embedded(2)
    return null
}

private fun parseIpv4Literal(text: String): IntArray? {
    val parts = text.split(".")
    if (parts.size == IPV4_OCTET_COUNT) {
        val octets = parts.mapNotNull { parseIpOctet(it) }
        return if (octets.size == IPV4_OCTET_COUNT) octets.toIntArray() else null
    }
    if (parts.size != 1) return null
    // A single decimal or hex integer is a valid IPv4 host for resolvers (2130706433 is 127.0.0.1).
    val number =
        when {
            text.startsWith("0x", ignoreCase = true) -> text.substring(HEX_PREFIX_LENGTH).toLongOrNull(HEX_RADIX)
            text.isNotEmpty() && text.all { it in '0'..'9' } -> text.toLongOrNull()
            else -> null
        } ?: return null
    if (number !in 0..MAX_IPV4_INTEGER) return null
    val mask = BYTE_MASK.toLong()
    return intArrayOf(
        ((number shr 24) and mask).toInt(),
        ((number shr 16) and mask).toInt(),
        ((number shr 8) and mask).toInt(),
        (number and mask).toInt(),
    )
}

/** Parses an IPv6 literal (compressed, dotted tail and zone id allowed) into its 16 bytes, or null when [text] is not one. */
private fun parseIpv6Literal(text: String): ByteArray? {
    var value = text.substringBefore('%').lowercase()
    if (':' !in value) return null
    val lastColon = value.lastIndexOf(':')
    var dottedTail: IntArray? = null
    val tail = value.substring(lastColon + 1)
    if ('.' in tail) {
        val octets = tail.split(".")
        if (octets.size != IPV4_OCTET_COUNT) return null
        val parsed = IntArray(IPV4_OCTET_COUNT)
        for ((index, octet) in octets.withIndex()) {
            parsed[index] = octet.toIntOrNull()?.takeIf { it in 0..MAX_OCTET_VALUE } ?: return null
        }
        dottedTail = parsed
        value = value.substring(0, lastColon + 1) + "0:0"
    }
    val compression = value.indexOf("::")
    if (compression != value.lastIndexOf("::")) return null

    fun groups(section: String): List<Int>? {
        if (section.isEmpty()) return emptyList()
        val result = mutableListOf<Int>()
        for (group in section.split(":")) {
            if (group.isEmpty() || group.length > IPV6_GROUP_MAX_DIGITS) return null
            result += group.toIntOrNull(HEX_RADIX) ?: return null
        }
        return result
    }

    val full: List<Int>
    if (compression >= 0) {
        val head = groups(value.substring(0, compression)) ?: return null
        val rest = groups(value.substring(compression + 2)) ?: return null
        if (head.size + rest.size >= IPV6_GROUP_COUNT) return null
        full = head + List(IPV6_GROUP_COUNT - head.size - rest.size) { 0 } + rest
    } else {
        full = groups(value) ?: return null
        if (full.size != IPV6_GROUP_COUNT) return null
    }
    val bytes = ByteArray(IPV6_GROUP_COUNT * 2)
    full.forEachIndexed { index, group ->
        bytes[index * 2] = (group shr 8).toByte()
        bytes[index * 2 + 1] = group.toByte()
    }
    dottedTail?.forEachIndexed { index, octet -> bytes[IPV6_PREFIX_BYTES + index] = octet.toByte() }
    return bytes
}

// IPv4 address range constants
private const val IPV4_OCTET_COUNT = 4
private const val IP_LOOPBACK = 127
private const val IP_LINK_LOCAL_A = 169
private const val IP_LINK_LOCAL_B = 254
private const val IP_PRIVATE_CLASS_A = 10
private const val IP_PRIVATE_CLASS_B = 172
private val IP_PRIVATE_B_RANGE = 16..31
private const val IP_PRIVATE_CLASS_C = 192
private const val IP_PRIVATE_C_SUBNET = 168
private const val IP_CGNAT_A = 100
private val IP_CGNAT_B_RANGE = 64..127
private const val IP_MULTICAST_A = 224
private const val IP_BENCHMARK_A = 198
private val IP_BENCHMARK_B_RANGE = 18..19
private const val HEX_RADIX = 16
private const val OCTAL_RADIX = 8
private const val MAX_OCTET_VALUE = 255
private const val BYTE_MASK = 0xFF
private const val MAX_IPV4_INTEGER = 0xFFFFFFFFL
private const val IPV6_GROUP_COUNT = 8
private const val IPV6_GROUP_MAX_DIGITS = 4
private const val IPV6_PREFIX_BYTES = 12
private const val IPV6_MAPPED_ZERO_BYTES = 10
private const val IPV6_TRANSLATED_ZERO_BYTES = 8
private const val IPV6_NAT64_ZERO_FROM = 4
private const val IPV6_LAST_BYTE = 15
private const val HEX_PREFIX_LENGTH = 2

/** Parse an IP octet supporting decimal, 0x hex, and 0-prefixed octal. */
private fun parseIpOctet(s: String): Int? =
    try {
        when {
            s.startsWith("0x", ignoreCase = true) -> s.substring(HEX_PREFIX_LENGTH).toInt(HEX_RADIX)
            s.startsWith("0") && s.length > 1 -> s.toInt(OCTAL_RADIX)
            else -> s.toInt()
        }.takeIf { it in 0..MAX_OCTET_VALUE }
    } catch (_: NumberFormatException) {
        null
    }


