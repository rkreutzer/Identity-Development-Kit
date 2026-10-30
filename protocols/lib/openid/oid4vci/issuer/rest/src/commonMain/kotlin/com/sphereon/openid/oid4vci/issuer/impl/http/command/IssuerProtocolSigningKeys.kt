/* Copyright 2026 Sphereon International B.V. Licensed under the Apache License, Version 2.0. */
package com.sphereon.openid.oid4vci.issuer.impl.http.command

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.error.IdkError
import com.sphereon.crypto.core.jose.Jwk
import com.sphereon.crypto.core.jose.generateJwkThumbprintUri
import com.sphereon.openid.oid4vci.issuer.config.Oid4vciIssuerConfigProvider
import com.sphereon.openid.oid4vci.issuer.format.SigningKeyMode
import com.sphereon.openid.oid4vci.issuer.impl.signing.IssuerKeyIdResolver
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Public credential keys for thumbprint references; names are resolved by the issuer configuration. */
internal suspend fun issuerThumbprintSigningJwks(
    config: Oid4vciIssuerConfigProvider,
    resolver: IssuerKeyIdResolver?,
): IdkResult<JsonObject?, IdkError> {
    val signing = config.credentialSigningConfigs()
    val names = linkedSetOf<String>()
    for (id in config.credentialConfigurations.keys) {
        val selected = signing[id] ?: continue
        if (selected.signingKeyMode != SigningKeyMode.JwkThumbprint) continue
        names += selected.signingKeyAlias?.takeIf(String::isNotBlank) ?: return unavailableProtocolSigningKey()
    }
    if (names.isEmpty()) return Ok(null)
    val source = resolver ?: return unavailableProtocolSigningKey()
    val keys = linkedMapOf<String, JsonObject>()
    for (name in names) {
        val material = source.resolvePublicJwk(name).getOrElse { return unavailableProtocolSigningKey() }
        val published = thumbprintSigningJwk(material).getOrElse { return unavailableProtocolSigningKey() }
        keys[(published.getValue("kid") as JsonPrimitive).content] = published
    }
    return Ok(JsonObject(mapOf("keys" to JsonArray(keys.entries.sortedBy { it.key }.map { it.value }))))
}

/** Uses the same public-key thumbprint URI as credential protected headers. */
internal fun thumbprintSigningJwk(material: JsonObject): IdkResult<JsonObject, IdkError> {
    if (material.keys.any { it in PRIVATE_JWK_MEMBERS } ||
        (material["kty"] as? JsonPrimitive)?.content !in setOf("EC", "RSA", "OKP")) return unavailableProtocolSigningKey()
    val public = JsonObject(material.filterKeys { it in PUBLIC_JWK_MEMBERS })
    val key = runCatching { Json.decodeFromJsonElement(Jwk.serializer(), public) }.getOrNull()
        ?: return unavailableProtocolSigningKey()
    val kid = runCatching { generateJwkThumbprintUri(key.toPublicKey()) }.getOrNull()
        ?: return unavailableProtocolSigningKey()
    return Ok(JsonObject(public + mapOf("kid" to JsonPrimitive(kid), "use" to JsonPrimitive("sig"))))
}

private fun unavailableProtocolSigningKey(): IdkResult<Nothing, IdkError> =
    Err(IdkError.fromString(code = "signing_key_unavailable", message = "Credential signing public key is unavailable"))

private val PUBLIC_JWK_MEMBERS = setOf("kty", "crv", "x", "y", "n", "e")
private val PRIVATE_JWK_MEMBERS = setOf("d", "k", "p", "q", "dp", "dq", "qi", "oth")
