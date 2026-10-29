/*
 * Copyright 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

package com.sphereon.credential.claims.mapper.impl.resolver

import com.sphereon.cbor.CborItem
import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.decodeFromBase64Url
import com.sphereon.core.api.encodeToBase64
import com.sphereon.core.api.error.IdkError
import com.sphereon.credential.claims.mapper.api.error.ClaimMappingErrors
import com.sphereon.credential.claims.mapper.api.resolver.CredentialClaimResolver
import com.sphereon.mdoc.data.device.DataElementIdentifier
import com.sphereon.mdoc.data.device.IssuerSigned
import com.sphereon.mdoc.data.device.IssuerSignedCborCodec
import com.sphereon.mdoc.data.device.NameSpace
import com.sphereon.openid.oid4vp.common.CredentialFormat
import dev.zacsweers.metro.AppScope
import dev.zacsweers.metro.ContributesIntoSet
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.binding
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Extracts holder-visible data elements from an ISO mdoc IssuerSigned credential. */
@Inject
@ContributesIntoSet(AppScope::class, binding = binding<CredentialClaimResolver>())
class MdocClaimResolver(
    private val issuerSignedCborCodec: IssuerSignedCborCodec,
) : CredentialClaimResolver {
    override val supportedFormats: Set<CredentialFormat> = setOf(CredentialFormat.MSO_MDOC)

    override suspend fun extractAllClaims(
        credential: String,
        format: CredentialFormat,
        disclosedClaims: JsonObject?,
    ): IdkResult<Map<String, JsonElement>, IdkError> =
        decodeClaims(credential, format)

    override suspend fun extractClaims(
        credential: String,
        format: CredentialFormat,
        claimPaths: List<List<String>>,
        disclosedClaims: JsonObject?,
    ): IdkResult<Map<String, JsonElement>, IdkError> {
        val decoded = decodeClaims(credential, format)
        if (decoded.isErr) return Err(decoded.error)
        val requested = claimPaths.map(::claimPathKey).toSet()
        return Ok(decoded.value.filterKeys(requested::contains))
    }

    override suspend fun extractClaim(
        credential: String,
        format: CredentialFormat,
        claimPath: List<String>,
        disclosedClaims: JsonObject?,
    ): IdkResult<JsonElement?, IdkError> {
        if (claimPath.size != 2) return if (supports(format)) Ok(null) else extractionFailure("Unsupported credential format '${format.value}'")
        val decoded = decodeIssuerSigned(credential, format)
        if (decoded.isErr) return Err(decoded.error)
        val item = decoded.value.getIssuerSignedItem(NameSpace(claimPath[0]), DataElementIdentifier(claimPath[1]))
        return Ok(item?.elementValue?.toJsonElement())
    }

    private fun decodeClaims(
        credential: String,
        format: CredentialFormat,
    ): IdkResult<Map<String, JsonElement>, IdkError> {
        val decoded = decodeIssuerSigned(credential, format)
        if (decoded.isErr) return Err(decoded.error)
        return Ok(decoded.value.toClaims())
    }

    private fun decodeIssuerSigned(
        credential: String,
        format: CredentialFormat,
    ): IdkResult<IssuerSigned, IdkError> {
        if (!supports(format)) return extractionFailure("Unsupported credential format '${format.value}'")
        val bytes = try {
            credential.decodeFromBase64Url()
        } catch (expected: Throwable) {
            return extractionFailure("The mdoc credential is not valid base64url", expected)
        }
        val decoded = issuerSignedCborCodec.decode(bytes)
        if (decoded.isErr) {
            return extractionFailure("Failed to decode mdoc IssuerSigned data: ${decoded.error.message}", decoded.error.exception)
        }
        return Ok(decoded.value.value)
    }

    private fun IssuerSigned.toClaims(): Map<String, JsonElement> =
        getAllIssuerSignedItems()
            .orEmpty()
            .flatMap { (namespace, items) ->
                items.map { item ->
                    claimPathKey(listOf(namespace.toString(), item.elementIdentifier.toString())) to item.elementValue.toJsonElement()
                }
            }.toMap(linkedMapOf())

    private fun <T> extractionFailure(
        reason: String,
        cause: Throwable? = null,
    ): IdkResult<T, IdkError> =
        Err(
            ClaimMappingErrors.claimExtractionFailed(
                credentialId = "unknown",
                reason = reason,
                cause = cause,
            ),
        )
}

private fun claimPathKey(path: List<String>): String = path.joinToString(".")

private fun Any?.toJsonElement(): JsonElement = when (this) {
    null -> JsonNull
    is JsonElement -> this
    is String -> JsonPrimitive(this)
    is Char -> JsonPrimitive(toString())
    is Boolean -> JsonPrimitive(this)
    is Byte -> JsonPrimitive(toInt())
    is Short -> JsonPrimitive(toInt())
    is Int -> JsonPrimitive(this)
    is Long -> JsonPrimitive(this)
    is Float -> if (isFinite()) JsonPrimitive(this) else JsonPrimitive(toString())
    is Double -> if (isFinite()) JsonPrimitive(this) else JsonPrimitive(toString())
    is UByte -> JsonPrimitive(toInt())
    is UShort -> JsonPrimitive(toInt())
    is UInt -> JsonPrimitive(toLong())
    is ULong -> JsonPrimitive(toString())
    is ByteArray -> toSafeBinaryJson()
    is CborItem<*> -> try {
        toJsonSimple()
    } catch (_: Throwable) {
        value.toJsonElement()
    }
    is Map<*, *> -> JsonObject(
        entries.associate { (key, value) -> key.toJsonObjectKey() to value.toJsonElement() },
    )
    is Iterable<*> -> JsonArray(map { it.toJsonElement() })
    is Array<*> -> JsonArray(map { it.toJsonElement() })
    else -> JsonPrimitive(toString())
}

private fun Any?.toJsonObjectKey(): String = when (this) {
    is CborItem<*> -> try {
        toJsonSimple().let { (it as? JsonPrimitive)?.content ?: it.toString() }
    } catch (_: Throwable) {
        value.toString()
    }
    else -> toString()
}

private fun ByteArray.toSafeBinaryJson(): JsonPrimitive {
    val mediaType = when {
        size >= 3 && this[0] == 0xff.toByte() && this[1] == 0xd8.toByte() && this[2] == 0xff.toByte() -> "image/jpeg"
        size >= 8 && copyOfRange(0, 8).contentEquals(PNG_SIGNATURE) -> "image/png"
        size >= 12 && decodeToString(0, 4) == "RIFF" && decodeToString(8, 12) == "WEBP" -> "image/webp"
        else -> null
    }
    return if (mediaType == null) JsonPrimitive("Binary data (${size} bytes)")
    else JsonPrimitive("data:$mediaType;base64,${encodeToBase64()}")
}

private val PNG_SIGNATURE = byteArrayOf(0x89.toByte(), 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a)
