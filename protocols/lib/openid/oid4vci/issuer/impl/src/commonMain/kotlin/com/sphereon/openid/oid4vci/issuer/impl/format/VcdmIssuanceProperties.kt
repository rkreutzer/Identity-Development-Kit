/*
 * © 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

package com.sphereon.openid.oid4vci.issuer.impl.format

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.error.IdkError
import com.sphereon.openid.oid4vc.common.vcdm.VcdmVersion
import com.sphereon.openid.oid4vci.issuer.format.IssuanceContext
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * Merge the lossless caller-supplied top-level semantic properties into an issuer-built VCDM
 * document. Server-owned fields are rejected explicitly: silently dropping one would make the
 * caller's requested document differ from the signed document and would hide a key-material or
 * issuer substitution attempt.
 */
internal fun mergeVcdmIssuanceProperties(
    context: IssuanceContext,
    version: VcdmVersion,
): IdkResult<JsonObject, IdkError> {
    val properties = context.vcdmProperties
    val protected = properties.keys intersect SERVER_CONTROLLED_VCDM_KEYS
    if (protected.isNotEmpty()) {
        return Err(
            invalidVcdmIssuance(
                "caller-supplied VCDM properties cannot override server-controlled fields: ${protected.sorted().joinToString()}",
            ),
        )
    }

    val versionOnly = when (version) {
        VcdmVersion.V1_1 -> VCDM_2_ONLY_PROPERTIES
        VcdmVersion.V2_0 -> emptySet()
        else -> emptySet()
    }
    val unsupported = properties.keys intersect versionOnly
    if (unsupported.isNotEmpty()) {
        return Err(
            invalidVcdmIssuance(
                "VCDM ${version.value} does not support top-level properties: ${unsupported.sorted().joinToString()}",
            ),
        )
    }

    val termsOfUse =
        context.federationEntityIdentifier?.let { entityIdentifier ->
            federationTermsOfUse(properties[TERMS_OF_USE], entityIdentifier).getOrElse { return Err(it) }
        }

    return Ok(
        buildJsonObject {
            properties.forEach { (name, value) -> put(name, value) }
            termsOfUse?.let { put(TERMS_OF_USE, it) }
        },
    )
}

/**
 * The `termsOfUse` of a credential issued by an OpenID Federation entity (DIIP v5 Appendix B): an
 * entry of type `OpenIDFederation` whose `policyId` is the issuer's Entity Identifier, so a
 * verifier can find the issuer's trust chain. `trustFramework` is optional in the profile and is
 * omitted because the issuer has no authoritative name for the federation to put there.
 *
 * Caller-supplied terms of use are kept; the federation entry is appended, turning a single entry
 * into an array. A caller-supplied `OpenIDFederation` entry is refused: only the issuer may state
 * which federation entity it is.
 */
private fun federationTermsOfUse(
    supplied: JsonElement?,
    entityIdentifier: String,
): IdkResult<JsonElement, IdkError> {
    val federationEntry =
        buildJsonObject {
            put("type", OPENID_FEDERATION_TERMS_OF_USE_TYPE)
            put("policyId", entityIdentifier)
        }
    val existing =
        when (supplied) {
            null -> return Ok(federationEntry)
            is JsonObject -> listOf(supplied)
            is JsonArray -> supplied.toList()
            else -> return Err(invalidVcdmIssuance("termsOfUse must be an object or an array of objects"))
        }
    if (existing.any { it !is JsonObject }) {
        return Err(invalidVcdmIssuance("termsOfUse must be an object or an array of objects"))
    }
    if (existing.any { (it as JsonObject).declaresType(OPENID_FEDERATION_TERMS_OF_USE_TYPE) }) {
        return Err(invalidVcdmIssuance("an $OPENID_FEDERATION_TERMS_OF_USE_TYPE termsOfUse entry is set by the issuer and cannot be supplied"))
    }
    return Ok(JsonArray(existing + federationEntry))
}

private fun JsonObject.declaresType(type: String): Boolean =
    when (val declared = this["type"]) {
        is JsonPrimitive -> declared.isString && declared.content == type
        is JsonArray -> declared.any { it is JsonPrimitive && it.isString && it.content == type }
        else -> false
    }

private const val TERMS_OF_USE: String = "termsOfUse"

/** `termsOfUse.type` naming an OpenID Federation entity as the issuer (DIIP v5 Appendix B). */
internal const val OPENID_FEDERATION_TERMS_OF_USE_TYPE: String = "OpenIDFederation"

internal fun invalidVcdmIssuance(message: String): IdkError =
    IdkError.fromString(code = "invalid_vcdm_credential", message = message)

internal const val VERIFIABLE_CREDENTIAL_TYPE: String = "VerifiableCredential"

/**
 * The `type` of an issued VCDM 1.1 or 2.0 credential: `VerifiableCredential` followed by the
 * configured specific types. A credential typed only as `VerifiableCredential` says nothing about
 * what it attests, so issuance is refused instead of producing one.
 */
internal fun vcdmCredentialTypes(configured: List<String>?): IdkResult<List<String>, IdkError> {
    val specific =
        configured.orEmpty()
            .map(String::trim)
            .filter { it.isNotEmpty() && it != VERIFIABLE_CREDENTIAL_TYPE }
            .distinct()
    if (specific.isEmpty()) {
        return Err(invalidVcdmIssuance("credential_definition.type must name at least one type besides $VERIFIABLE_CREDENTIAL_TYPE"))
    }
    return Ok(listOf(VERIFIABLE_CREDENTIAL_TYPE) + specific)
}

/** Fields that issuance always derives from trusted protocol/configuration state. */
internal val SERVER_CONTROLLED_VCDM_KEYS: Set<String> = setOf(
    "@context", "type", "issuer", "credentialSubject", "validFrom", "validUntil",
    "issuanceDate", "expirationDate", "id", "credentialStatus", "status", "proof", "vc", "vp",
    "iss", "sub", "iat", "nbf", "exp", "jti", "cnf", "kid", "jwk", "x5c",
)

private val VCDM_2_ONLY_PROPERTIES: Set<String> = setOf("name", "description", "relatedResource")
