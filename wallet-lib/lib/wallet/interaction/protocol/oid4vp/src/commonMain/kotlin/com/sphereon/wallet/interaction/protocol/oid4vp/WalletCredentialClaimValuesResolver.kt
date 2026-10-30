/*
 * Copyright 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

package com.sphereon.wallet.interaction.protocol.oid4vp

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.error.IdkError
import com.sphereon.credential.claims.mapper.api.error.ClaimMappingErrors
import com.sphereon.credential.claims.mapper.api.mapper.ClaimsMappingService
import com.sphereon.credential.claims.mapper.api.model.CredentialWithId
import com.sphereon.credential.claims.mapper.api.resolver.CredentialClaimResolver
import com.sphereon.sdjwt.SdJwtCodec
import com.sphereon.wallet.credential.CredentialInstance
import com.sphereon.wallet.credential.CredentialRecord
import com.sphereon.wallet.credential.CredentialFormat
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlin.time.Clock

/**
 * Projects typed, holder-visible claim values from a wallet record through the existing
 * format-specific claim resolver set. Keys use the resolver's dotted claim-path representation;
 * mdoc keys therefore retain both namespace and element name.
 */
class WalletCredentialClaimValuesResolver(
    private val claimsMappingService: ClaimsMappingService,
    private val clock: Clock = Clock.System,
    private val credentialClaimResolvers: Set<CredentialClaimResolver> = emptySet(),
) {
    /**
     * Resolve values from the record's currently presentable active instance, or from the exact
     * [credentialInstanceId] when supplied. An explicit instance must still be active and valid.
     */
    suspend fun resolve(
        record: CredentialRecord,
        credentialInstanceId: String? = null,
    ): IdkResult<Map<String, JsonElement>, IdkError> {
        val now = clock.now()
        val instance =
            if (credentialInstanceId == null) {
                record.presentableOid4vpInstance(now)
            } else {
                record.instances.firstOrNull { it.id == credentialInstanceId }
            } ?: return extractionError(record.id, "No presentable credential instance was found")

        if (record.deletedAt != null || !instance.isPresentableOid4vpInstance(now)) {
            return extractionError(record.id, "The selected credential instance is not active and valid")
        }
        val raw = instance.raw ?: return extractionError(record.id, "The credential body is not loaded")

        return claimsMappingService.extractAllClaims(
            CredentialWithId(
                credentialId = instance.id,
                format = instance.format,
                payload = raw,
            ),
        )
    }

    /**
     * Check a DCQL path against the same active instance used to resolve [claimValues]. Exact mdoc
     * namespace/element lookup is delegated to the format resolver because its display map is flat.
     */
    suspend fun containsDisclosurePath(
        record: CredentialRecord,
        credentialInstanceId: String,
        path: List<JsonElement>,
    ): Boolean {
        val instance = record.instances.firstOrNull { it.id == credentialInstanceId } ?: return false
        if (record.deletedAt != null || !instance.isPresentableOid4vpInstance(clock.now())) return false
        val raw = instance.raw ?: return false
        val resolver = credentialClaimResolvers.singleOrNull { it.supports(instance.format) } ?: return false
        if (instance.format.isMdoc) {
            if (path.size != 2) return false
            val namespace = (path[0] as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull ?: return false
            val element = (path[1] as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull ?: return false
            val result = resolver.extractClaim(raw, instance.format, listOf(namespace, element))
            return result.isOk && result.value != null
        }
        if (instance.format == CredentialFormat.SD_JWT_VC || instance.format == CredentialFormat.W3C_VC_SD_JWT) {
            val parsed = SdJwtCodec.parse(raw)
            if (parsed.isErr) return false
            return parsed.value.payload.fullPayload.containsDisclosurePath(path)
        }
        val pathSegments = mutableListOf<String>()
        for (component in path) {
            val property = (component as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull ?: return false
            pathSegments += property
        }
        val result = resolver.extractClaim(raw, instance.format, pathSegments)
        return result.isOk && result.value != null
    }

    private fun extractionError(
        credentialId: String,
        reason: String,
    ): IdkResult<Map<String, JsonElement>, IdkError> =
        Err(ClaimMappingErrors.claimExtractionFailed(credentialId, reason))
}
