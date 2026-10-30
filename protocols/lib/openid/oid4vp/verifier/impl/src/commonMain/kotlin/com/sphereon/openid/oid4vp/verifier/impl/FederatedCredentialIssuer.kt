/*
 * Copyright 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

package com.sphereon.openid.oid4vp.verifier.impl

import com.sphereon.openid.oid4vp.verifier.CredentialIssuerControllerClaim
import com.sphereon.openid.oid4vp.verifier.TrustedAuthenticationPurpose
import com.sphereon.openid.oid4vp.verifier.TrustedAuthenticationResolution
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Issuer authentication through OpenID Federation for a credential issued under a DID (DIIP v5,
 * Appendix B, "OpenID Federation Digital Credentials Profile").
 *
 * Such a credential keeps its DID as `iss` (or VCDM `issuer`) and names the Issuer's Entity
 * Identifier in the `fed` claim (SD-JWT VC) or in the `policyId` of a `termsOfUse` entry of type
 * `OpenIDFederation` (VCDM). The verifier then admits it with the keys of that entity's `vc_issuer`
 * metadata, resolved through its Trust Chain: the credential's header `kid` must equal the `kid` of
 * one of those keys.
 *
 * The entity named by the credential only selects admitted material. It grants nothing until the
 * signature verifies against a key of exactly that entity's [CredentialIssuerControllerClaim.FEDERATION_ENTITY]
 * material. A DID the verifier admits directly keeps its DID admission; the federation path applies
 * only when no issuer material names that DID.
 */
internal object FederatedCredentialIssuer {
    const val FED_CLAIM = "fed"
    const val TERMS_OF_USE_TYPE = "OpenIDFederation"
    private const val MAX_IDENTIFIER_LENGTH = 2048

    /**
     * The Entity Identifier a credential payload names as its Issuer's federation entity, or null
     * when it names none, names a malformed value, or names different entities.
     */
    fun entityIdentifier(payload: JsonObject): String? {
        val named = linkedSetOf<String>()
        var malformed = false
        payload[FED_CLAIM]?.let { fed ->
            val value = (fed as? JsonPrimitive)?.takeIf { it.isString }?.content
            if (value == null) malformed = true else named += value
        }
        val vc = payload["vc"] as? JsonObject
        listOfNotNull(payload["termsOfUse"], vc?.get("termsOfUse")).forEach { termsOfUse ->
            val entries = when (termsOfUse) {
                is JsonArray -> termsOfUse
                else -> listOf(termsOfUse)
            }
            entries.forEach { entry ->
                val terms = entry as? JsonObject ?: return@forEach
                if (!hasFederationType(terms["type"])) return@forEach
                val policyId = (terms["policyId"] as? JsonPrimitive)?.takeIf { it.isString }?.content
                if (policyId == null) malformed = true else named += policyId
            }
        }
        if (malformed || named.size != 1) return null
        return named.single().takeIf(::isEntityIdentifier)
    }

    /** The DID a credential is issued under, or null when [issuer] is not a DID. */
    fun didIssuer(issuer: String?): String? = issuer?.takeIf { it.startsWith("did:") && it == it.trim() && '#' !in it }

    /** True when [authentications] hold issuer material that names [issuer] itself. */
    fun hasIssuerMaterial(issuer: String, authentications: List<TrustedAuthenticationResolution>): Boolean =
        authentications.any {
            it.purpose == TrustedAuthenticationPurpose.CREDENTIAL_ISSUER &&
                it.controllerClaim == CredentialIssuerControllerClaim.ISSUER &&
                it.controller == issuer
        }

    /**
     * The federation-entity material that applies to a credential with [issuer] and [payload], when the
     * federation path applies to it. Null means the path does not apply and the credential takes the DID
     * path exactly as one without a federation entity would: the issuer is not a DID, the credential
     * names no federation entity, verifier material names the DID itself, or the verifier has admitted
     * no material for the named entity. The named entity is unverified input, so ignoring it is never
     * weaker than the DID path. Otherwise every [CredentialIssuerControllerClaim.FEDERATION_ENTITY]
     * source for exactly the named entity is returned; more than one is ambiguous and fails closed.
     */
    fun applicableSources(
        issuer: String?,
        payload: JsonObject?,
        authentications: List<TrustedAuthenticationResolution>,
    ): Applicable? {
        val did = didIssuer(issuer) ?: return null
        val entity = payload?.let(::entityIdentifier) ?: return null
        if (hasIssuerMaterial(did, authentications)) return null
        val sources = authentications.filter {
            it.purpose == TrustedAuthenticationPurpose.CREDENTIAL_ISSUER &&
                it.controllerClaim == CredentialIssuerControllerClaim.FEDERATION_ENTITY &&
                it.controller == entity &&
                it.trustedJwks != null
        }
        if (sources.isEmpty()) return null
        return Applicable(entity = entity, sources = sources)
    }

    /**
     * A credential `kid` usable with federation-entity material: a DID URL of [did], either absolute or
     * a relative `#fragment`. It is matched against the `vc_issuer` keys exactly as presented.
     */
    fun isDidUrlOf(did: String, kid: String): Boolean =
        (kid.startsWith("#") && kid.length > 1) || (kid.startsWith("$did#") && kid.length > did.length + 1)

    fun isEntityIdentifier(value: String): Boolean =
        value.startsWith("https://") && value.length > "https://".length && value.length <= MAX_IDENTIFIER_LENGTH &&
            '#' !in value && value.none { it.isWhitespace() }

    private fun hasFederationType(type: JsonElement?): Boolean =
        (type as? JsonPrimitive)?.takeIf { it.isString }?.content == TERMS_OF_USE_TYPE

    data class Applicable(
        val entity: String,
        val sources: List<TrustedAuthenticationResolution>,
    )
}
