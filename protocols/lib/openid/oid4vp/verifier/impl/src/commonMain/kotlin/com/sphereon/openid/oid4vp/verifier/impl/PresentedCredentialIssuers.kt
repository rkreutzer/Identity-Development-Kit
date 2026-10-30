/*
 * Copyright 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

package com.sphereon.openid.oid4vp.verifier.impl

import com.sphereon.core.api.decodeFromBase64Url
import com.sphereon.openid.oid4vp.verifier.CredentialIssuerAuthenticationLookup
import com.sphereon.openid.oid4vp.verifier.CredentialIssuerControllerClaim
import com.sphereon.openid.oid4vp.verifier.TrustedAuthenticationPurpose
import com.sphereon.openid.oid4vp.verifier.TrustedAuthenticationResolution
import kotlinx.coroutines.CancellationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject

/**
 * Credential issuers named by the presentations of one response, used only to select which issuers the
 * verifier's [CredentialIssuerAuthenticationLookup] resolves before the credentials are verified.
 *
 * The values are read from unverified credentials. They never become key material or trust: each
 * resolved entry is admitted material from verifier policy, and every credential is still verified
 * against it by the normal issuer-authentication path. Https issuers are selected, and for a credential
 * issued under a DID, the OpenID Federation entity it names in `fed` or an `OpenIDFederation`
 * `termsOfUse` (see [FederatedCredentialIssuer]). Other DID issuers resolve through their DID
 * documents, X.509 issuers through their configured chain.
 */
internal object PresentedCredentialIssuers {
    const val MAX_ISSUERS = 16
    private const val MAX_DEPTH = 3
    private const val VC_JWT_DATA_PREFIX = "data:application/vc+jwt,"
    private val json = Json { ignoreUnknownKeys = true }

    fun collect(presentations: Collection<JsonElement>): List<String> = collected(presentations).issuers.toList()

    /** Federation entities named by credentials issued under a DID, each with the DIDs that name it. */
    fun collectFederationEntities(presentations: Collection<JsonElement>): Map<String, Set<String>> = collected(presentations).entities

    private fun collected(presentations: Collection<JsonElement>): Collected {
        val collected = Collected()
        presentations.forEach { element ->
            val compact = (element as? JsonPrimitive)?.takeIf { it.isString }?.content ?: return@forEach
            collectCompact(compact, collected, 0)
        }
        return collected
    }

    /**
     * Resolves admitted material for every presented https issuer that [existing] does not already
     * name. A lookup error, a result for another controller or purpose, or a result that is not an
     * admitted public JWK Set yields no entry, so that credential later fails the normal exact-source
     * requirement.
     */
    suspend fun resolve(
        presentations: Collection<JsonElement>,
        existing: List<TrustedAuthenticationResolution>,
        lookup: CredentialIssuerAuthenticationLookup,
    ): List<TrustedAuthenticationResolution> {
        val configured = existing.filter {
            it.purpose == TrustedAuthenticationPurpose.CREDENTIAL_ISSUER && it.controllerClaim == CredentialIssuerControllerClaim.ISSUER
        }.map { it.controller }.toSet()
        val collected = collected(presentations)
        val resolved = mutableListOf<TrustedAuthenticationResolution>()
        for (issuer in collected.issuers) {
            if (issuer in configured) continue
            val result = try {
                lookup.resolve(issuer)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                continue
            }
            if (result.isErr) continue
            val admitted = result.value ?: continue
            if (admitted.controller != issuer || admitted.purpose != TrustedAuthenticationPurpose.CREDENTIAL_ISSUER) continue
            if (admitted.controllerClaim != CredentialIssuerControllerClaim.ISSUER) continue
            // Only an admitted public JWK Set is accepted on demand. Identifier material (X.509 chains in
            // particular) would also act response-wide, for example as mdoc status roots for every
            // presented credential, so it must come from the verifier's configured trust instead.
            if (admitted.trustedJwks == null) continue
            resolved += admitted
        }
        val configuredEntities = existing.filter {
            it.purpose == TrustedAuthenticationPurpose.CREDENTIAL_ISSUER && it.controllerClaim == CredentialIssuerControllerClaim.FEDERATION_ENTITY
        }.map { it.controller }.toSet()
        for ((entity, dids) in collected.entities) {
            if (entity in configuredEntities) continue
            // A DID the verifier admits directly keeps that admission (see FederatedCredentialIssuer).
            if (dids.all { it in configured }) continue
            val result = try {
                lookup.resolveFederationEntity(entity)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                continue
            }
            if (result.isErr) continue
            val admitted = result.value ?: continue
            if (admitted.controller != entity || admitted.purpose != TrustedAuthenticationPurpose.CREDENTIAL_ISSUER) continue
            if (admitted.controllerClaim != CredentialIssuerControllerClaim.FEDERATION_ENTITY || admitted.trustedJwks == null) continue
            resolved += admitted
        }
        return resolved
    }

    private class Collected {
        val issuers = linkedSetOf<String>()
        val entities = linkedMapOf<String, MutableSet<String>>()
        val full: Boolean get() = issuers.size >= MAX_ISSUERS && entities.size >= MAX_ISSUERS
    }

    private fun collectCompact(compact: String, collected: Collected, depth: Int) {
        if (depth > MAX_DEPTH || collected.full) return
        // An SD-JWT presentation starts with its issuer-signed JWT; disclosures and the KB-JWT follow '~'.
        val payload = payload(compact.substringBefore('~')) ?: return
        val vc = payload["vc"] as? JsonObject
        listOfNotNull(httpsIssuer(payload["iss"]), httpsIssuer(vc?.get("issuer") ?: payload["issuer"])).forEach { issuer ->
            if (collected.issuers.size < MAX_ISSUERS) collected.issuers += issuer
        }
        val did = FederatedCredentialIssuer.didIssuer(identifier(payload["iss"]) ?: identifier(vc?.get("issuer") ?: payload["issuer"]))
        val entity = did?.let { FederatedCredentialIssuer.entityIdentifier(payload) }
        if (did != null && entity != null && (entity in collected.entities || collected.entities.size < MAX_ISSUERS)) {
            collected.entities.getOrPut(entity) { linkedSetOf() } += did
        }
        val vp = payload["vp"] as? JsonObject ?: payload.takeIf { it.containsKey("verifiableCredential") }
        val children = when (val credentials = vp?.get("verifiableCredential")) {
            is JsonArray -> credentials
            null -> emptyList()
            else -> listOf(credentials)
        }
        children.forEach { child ->
            val nested = when (child) {
                is JsonPrimitive -> child.takeIf { it.isString }?.content
                is JsonObject -> (child["id"] as? JsonPrimitive)?.takeIf { it.isString }?.content
                    ?.takeIf { it.startsWith(VC_JWT_DATA_PREFIX) }?.removePrefix(VC_JWT_DATA_PREFIX)
                else -> null
            }
            nested?.let { collectCompact(it, collected, depth + 1) }
        }
    }

    private fun payload(jwt: String): JsonObject? {
        val parts = jwt.split('.')
        if (parts.size != 3) return null
        return runCatching { json.parseToJsonElement(parts[1].decodeFromBase64Url().decodeToString()).jsonObject }.getOrNull()
    }

    private fun identifier(element: JsonElement?): String? =
        when (element) {
            is JsonPrimitive -> element.takeIf { it.isString }?.content
            is JsonObject -> (element["id"] as? JsonPrimitive)?.takeIf { it.isString }?.content
            else -> null
        }

    private fun httpsIssuer(element: JsonElement?): String? {
        val value = identifier(element) ?: return null
        return value.takeIf {
            it.startsWith("https://") && it == it.trim() && it.length <= 2048 && '#' !in it && it.none { c -> c.isWhitespace() }
        }
    }
}
