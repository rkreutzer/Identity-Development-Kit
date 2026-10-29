package com.sphereon.wallet.unit.attestation

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.contentOrNull

/** OpenID4VCI 1.0 Appendix D.1. This wire format is independent of ETSI TS03. */
@Serializable
data class Oid4vciKeyAttestationClaims(
    val iss: String,
    val iat: Long,
    val exp: Long,
    val nonce: String,
    @SerialName("attested_keys") val attestedKeys: List<JsonObject>,
) {
    init {
        require(iss.isNotBlank() && nonce.isNotBlank() && exp > iat)
        require(attestedKeys.isNotEmpty())
        require(attestedKeys.all { key ->
            key["kty"]?.jsonPrimitive?.contentOrNull in setOf("EC", "RSA", "OKP") && key.keys.none { it in PRIVATE_JWK_MEMBERS }
        }) { "OID4VCI key attestation requires public asymmetric JWKs" }
    }

    companion object {
        private val PRIVATE_JWK_MEMBERS = setOf("d", "p", "q", "dp", "dq", "qi", "oth", "k")
    }
}
