/* Copyright 2026 Sphereon International B.V. */

package com.sphereon.oauth2.server.authorization.signing



import com.sphereon.crypto.core.generic.SignatureAlgorithm



/** Actual AS JWS mapping used by server discovery/signing; distinct from generic KMS/verifier capability. */

object AsServerSigningAlgorithms {

    private val names: Map<SignatureAlgorithm,String> = linkedMapOf(

        SignatureAlgorithm.RSA_SHA256 to "RS256",
        SignatureAlgorithm.RSA_SHA384 to "RS384",
        SignatureAlgorithm.RSA_SHA512 to "RS512",
        SignatureAlgorithm.ECDSA_SHA256 to "ES256",
        SignatureAlgorithm.ECDSA_SHA384 to "ES384",
        SignatureAlgorithm.ECDSA_SHA512 to "ES512",
        SignatureAlgorithm.ED25519 to "EdDSA",
        SignatureAlgorithm.RSA_SSA_PSS_SHA256_MGF1 to "PS256",
        SignatureAlgorithm.RSA_SSA_PSS_SHA384_MGF1 to "PS384",
        SignatureAlgorithm.RSA_SSA_PSS_SHA512_MGF1 to "PS512",
    )

    val supportedAlgorithms: Set<SignatureAlgorithm> get()=names.keys.toSet()

    fun joseName(algorithm: SignatureAlgorithm): String? = names[algorithm]

}

