/*
 * (c) 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

package com.sphereon.openid.oid4vp.verifier

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.compat.JsExportCompat
import com.sphereon.crypto.core.jose.Jwk
import com.sphereon.crypto.resolution.IdentifierOptsOrResult
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlin.experimental.ExperimentalObjCName
import kotlin.native.ObjCName

/**
 * Trust-admitted authentication material for one exact VCDM controller and one use.
 *
 * The controller is the issuer for a VC or the holder for a VP. It is selected from the
 * authenticated VCDM claims and is never taken from JOSE header key material. [identifier] is
 * resolved through the canonical identifier-resolution graph (DID, X.509, JWKS, or managed key),
 * while [trustedJwks] is an already admitted public JWKS. Exactly one list entry must match a
 * controller; ambiguity is rejected by the verifier.
 */
@Serializable
@JsExportCompat
@OptIn(ExperimentalObjCName::class)
@ObjCName("TrustedAuthenticationResolution", exact = true)
data class TrustedAuthenticationResolution(
    val controller: String,
    @Transient val identifier: IdentifierOptsOrResult? = null,
    val trustedJwks: JsonObject? = null,
    /** Keeps holder authentication separate from credential-issuer authentication policy. */
    val purpose: TrustedAuthenticationPurpose = TrustedAuthenticationPurpose.HOLDER,
    /** Admitted mdoc types for this material; null is unrestricted, an empty set permits none. */
    val documentTypes: Set<String>? = null,
    /** Authenticated certificate profile identifiers retained from the admission policy. */
    val certificateProfiles: Set<String> = emptySet(),
    /** Which credential claim names [controller]; see [CredentialIssuerControllerClaim]. */
    val controllerClaim: CredentialIssuerControllerClaim = CredentialIssuerControllerClaim.ISSUER,
) {
    init {
        require(
            controllerClaim == CredentialIssuerControllerClaim.ISSUER ||
                (purpose == TrustedAuthenticationPurpose.CREDENTIAL_ISSUER && trustedJwks != null),
        ) {
            "trusted_authentication_federation_entity_requires_credential_issuer_jwks"
        }
        require(documentTypes == null || documentTypes.all { it.isNotBlank() }) { "trusted_authentication_document_type_blank" }
        require(certificateProfiles.all { it.isNotBlank() }) { "trusted_authentication_certificate_profile_blank" }
        require(controller.isNotBlank()) { "trusted_authentication_resolution_controller_blank" }
        require((identifier != null) xor (trustedJwks != null)) {
            "trusted_authentication_resolution_requires_exactly_one_source"
        }
        if (trustedJwks != null) {
            val keys = trustedJwks["keys"]
            require(keys is JsonArray && keys.isNotEmpty() && keys.all { it is JsonObject }) {
                "trusted_authentication_resolution_trusted_jwks_invalid"
            }
            keys.forEach { element ->
                val key = element as JsonObject
                val kid = key["kid"] as? JsonPrimitive
                val parsed = runCatching { Jwk.fromJsonObject(key) }.getOrNull()
                require(
                    kid?.isString == true && kid.content.isNotBlank() && parsed != null &&
                        parsed.d == null && parsed.p == null && parsed.q == null &&
                        parsed.dP == null && parsed.dQ == null && parsed.qInv == null &&
                        parsed.k == null && parsed.x5c == null && parsed.x5t == null &&
                        parsed.x5u == null && parsed.x5t_S256 == null,
                ) {
                    "trusted_authentication_resolution_trusted_jwk_must_be_public_signing_key"
                }
            }
        }
    }
}

@Serializable
@JsExportCompat
@OptIn(ExperimentalObjCName::class)
@ObjCName("TrustedAuthenticationPurpose", exact = true)
enum class TrustedAuthenticationPurpose {
    HOLDER,
    CREDENTIAL_ISSUER,
}

/**
 * The credential claim that names the controller of credential-issuer material.
 *
 * [ISSUER] is the credential's own issuer (`iss`, or the VCDM `issuer`). [FEDERATION_ENTITY] is the
 * OpenID Federation Entity Identifier that a credential issued under a DID names as its Issuer's
 * entity: the `fed` claim of an SD-JWT VC, or the `policyId` of a VCDM `termsOfUse` entry of type
 * `OpenIDFederation` (DIIP v5, Appendix B). Its material is the public JWK Set of that entity's
 * `vc_issuer` Entity Type, and it verifies only a credential that names the entity this way and
 * whose header `kid` equals the `kid` of one of those keys. Material of one kind never verifies a
 * credential through the other claim.
 */
@Serializable
@JsExportCompat
@OptIn(ExperimentalObjCName::class)
@ObjCName("CredentialIssuerControllerClaim", exact = true)
enum class CredentialIssuerControllerClaim {
    ISSUER,
    FEDERATION_ENTITY,
}

/**
 * On-demand credential-issuer authentication for one issuer named by a presented credential.
 *
 * Some trust frameworks admit issuers that cannot be listed in advance; an OpenID Federation Trust
 * Anchor, for example, admits every entity whose Trust Chain resolves to it. The verifier calls this
 * lookup with the issuer identifier of a credential it is about to verify when no pre-resolved
 * [TrustedAuthenticationResolution] names that issuer. The issuer value only selects what to resolve:
 * implementations decide admission from persisted verifier policy and return already-admitted
 * material for exactly that controller with [TrustedAuthenticationPurpose.CREDENTIAL_ISSUER], or
 * `null` when the issuer is not admitted. The credential signature is still verified against the
 * returned material, so naming an issuer grants nothing by itself.
 */
fun interface CredentialIssuerAuthenticationLookup {
    suspend fun resolve(issuer: String): IdkResult<TrustedAuthenticationResolution?, IdkError>

    /**
     * The `vc_issuer` keys of the OpenID Federation entity a presented credential names in `fed` or in
     * an `OpenIDFederation` `termsOfUse` while it is issued under a DID (DIIP v5, Appendix B).
     *
     * [entityIdentifier] is read from the unverified credential and only selects what to resolve.
     * Implementations resolve its Trust Chain under persisted verifier policy and return the public
     * keys of its `vc_issuer` Resolved Metadata, unchanged and with their `kid` values, as material for
     * exactly that controller with [TrustedAuthenticationPurpose.CREDENTIAL_ISSUER] and
     * [CredentialIssuerControllerClaim.FEDERATION_ENTITY]; `null` when the entity is not admitted or
     * publishes no `vc_issuer` keys. The default admits no federation entity.
     */
    suspend fun resolveFederationEntity(entityIdentifier: String): IdkResult<TrustedAuthenticationResolution?, IdkError> = Ok(null)
}
