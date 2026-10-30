/*
 * (c) 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

package com.sphereon.openid.oid4vp.verifier.impl

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.binary.TypeToken
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.session.asCoreApiServiceGraph
import com.sphereon.crypto.core.kms.KeyManagerService
import com.sphereon.crypto.core.kms.asKeyManagerServiceGraph
import com.sphereon.crypto.jose.jws.JwsCompact
import com.sphereon.crypto.jose.jws.JwtService
import com.sphereon.crypto.jose.jws.JwtServiceImpl
import com.sphereon.crypto.jose.jws.command.VerifyJwsArgs
import com.sphereon.crypto.kms.provider.software.SoftwareKmsProviderConfig
import com.sphereon.crypto.kms.provider.software.SoftwareKmsProviderFactoryImpl
import com.sphereon.mdoc.data.DeviceAuthValidation
import com.sphereon.mdoc.data.MdocValidations
import com.sphereon.mdoc.data.device.DeviceResponseCborCodec
import com.sphereon.openid.oid4vc.common.CredentialFormat
import com.sphereon.openid.oid4vp.verifier.CredentialIssuerControllerClaim
import com.sphereon.openid.oid4vp.verifier.HolderBindingResult
import com.sphereon.openid.oid4vp.verifier.TrustedAuthenticationPurpose
import com.sphereon.openid.oid4vp.verifier.TrustedAuthenticationResolution
import com.sphereon.openid.oid4vp.verifier.VerifyHolderBindingArgs
import com.sphereon.openid.oid4vp.verifier.impl.testutil.Oid4vpVerifierTestContext
import com.sphereon.sdjwt.SdJwtCodec
import com.sphereon.sdjwt.SdJwtVerificationResult
import com.sphereon.sdjwt.VerifySdJwtArgs
import com.sphereon.sdjwt.command.VerifySdJwtCommand
import dev.whyoleg.cryptography.CryptographyProvider
import java.math.BigInteger
import java.lang.reflect.Proxy
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * DIIP v5 Appendix B with real ES256 signatures: an SD-JWT VC issued under did:web names its Issuer's
 * OpenID Federation entity in `fed`, and the verifier verifies it with the admitted `vc_issuer` JWK Set of
 * that entity, selecting the key by the exact header `kid` (a DID URL of the issuer DID).
 */
class FederatedCredentialIssuerSignatureTest {
    private val app = createOid4vpRpJvmTestAppGraph(this)
    private val session =
        app.userContextManager.getAnonymous().sessionContextManager.createOrGetFromId(
            "federated-credential-issuer-signature-test",
            principalType = com.sphereon.di.context.PrincipalType.USER,
        )
    private val testContext = Oid4vpVerifierTestContext("federated-credential-issuer-signature-test", this)
    private lateinit var jwtService: JwtService

    private val issuerKey = ecKeyPair()
    private val otherKey = ecKeyPair()

    @BeforeTest
    fun setUp() {
        val provider =
            (app as SoftwareKmsProviderFactoryImpl.Graph).softwareKmsProvider.create(
                SoftwareKmsProviderConfig(
                    id = "federated-credential-issuer-signature-test-provider",
                    cryptographyProvider = CryptographyProvider.Default.name,
                ),
                session.asCoreApiServiceGraph().serviceExecution,
            )
        val keyManager: KeyManagerService = session.graph.asKeyManagerServiceGraph().keyManagerService
        keyManager.registerProvider(provider, makeDefaultKms = true)
        jwtService = (session.graph as JwtServiceImpl.Graph).jwtService
    }

    @Test
    fun `fed credential verifies with the vc_issuer key whose kid equals the header kid`() = runTest {
        val result = verify(signedSdJwt(issuerKey, KID), vcIssuerJwks(OTHER_KID to otherKey, KID to issuerKey))

        assertTrue(result.verified, "the admitted vc_issuer key must verify: ${result.errors}")
        assertTrue(result.signatureValid)
    }

    @Test
    fun `fed credential is refused when no vc_issuer key carries the header kid`() = runTest {
        // The same key published under another kid does not match: kid selection is exact.
        val result = verify(signedSdJwt(issuerKey, KID), vcIssuerJwks("$DID#another-key" to issuerKey))

        assertFalse(result.verified)
        assertTrue(result.issuerTrustEstablished == false, "no admitted key must be selected: ${result.errors}")
    }

    @Test
    fun `fed credential is refused when the kid-selected vc_issuer key did not sign it`() = runTest {
        val result = verify(signedSdJwt(otherKey, KID), vcIssuerJwks(KID to issuerKey))

        assertFalse(result.verified)
        assertTrue(result.issuerCryptoVerified == false, "the signature must fail against the admitted key: ${result.errors}")
    }

    private suspend fun verify(presentation: String, jwks: JsonObject): HolderBindingResult {
        val command =
            VerifyHolderBindingCommandImpl(
                execution = testContext.execution,
                verifySdJwtCommand = IssuerSignatureVerifySdJwtCommand(jwtService),
                verifyJwsCommand = unused(),
                mdocValidations = unused<MdocValidations>(),
                deviceAuthValidation = unused<DeviceAuthValidation>(),
                deviceResponseCborCodec = unused<DeviceResponseCborCodec>(),
            )
        val result =
            command.execute(
                VerifyHolderBindingArgs(
                    presentation = presentation,
                    credentialFormat = CredentialFormat.SD_JWT_VC,
                    expectedNonce = "nonce",
                    expectedAudience = "https://verifier.example.com",
                    requireCryptographicHolderBinding = false,
                    trustedAuthentications =
                        listOf(
                            TrustedAuthenticationResolution(
                                controller = ENTITY,
                                trustedJwks = jwks,
                                purpose = TrustedAuthenticationPurpose.CREDENTIAL_ISSUER,
                                controllerClaim = CredentialIssuerControllerClaim.FEDERATION_ENTITY,
                            ),
                        ),
                ),
            )
        assertIs<Ok<*>>(result)
        return result.value
    }

    /**
     * Verifies only the issuer-signed JWT, through the production JWS verifier with the admitted JWK Set the
     * holder-binding command passes. Disclosure and key-binding checks are out of scope here.
     */
    private class IssuerSignatureVerifySdJwtCommand(private val jwtService: JwtService) : VerifySdJwtCommand {
        override val id: String = "issuer-signature-verify-sdjwt"
        override val isEnabled: Boolean = true
        override val inputTypeToken: TypeToken<VerifySdJwtArgs> = typeToken<VerifySdJwtArgs>()
        override val outputTypeToken: TypeToken<SdJwtVerificationResult> = typeToken<SdJwtVerificationResult>()

        override suspend fun execute(args: VerifySdJwtArgs): IdkResult<SdJwtVerificationResult, IdkError> {
            val parsed = SdJwtCodec.parse(args.sdJwt).getOrElse { return IdkResult.err(it) }
            val validation =
                jwtService.verifyJws(
                    VerifyJwsArgs(jws = JwsCompact(args.sdJwt.substringBefore('~')), identifier = args.identifier, trustedJwks = args.trustedJwks),
                ).getOrElse { return IdkResult.err(it) }
            val valid = validation.isValid && validation.cryptoVerified == true
            return Ok(
                SdJwtVerificationResult(
                    sdJwt = parsed,
                    signatureValid = valid,
                    disclosuresValid = true,
                    errorMessages = validation.errorMessages,
                    issuerTrustEstablished = validation.trustEstablished,
                    issuerCryptoVerified = validation.cryptoVerified,
                ),
            )
        }
    }

    private fun signedSdJwt(signer: KeyPair, kid: String): String {
        val header = """{"alg":"ES256","typ":"dc+sd-jwt","kid":"$kid"}"""
        val payload = """{"iss":"$DID","fed":"$ENTITY","vct":"https://example.com/vct","iat":1700000000}"""
        val input = "${b64(header.encodeToByteArray())}.${b64(payload.encodeToByteArray())}"
        val der = Signature.getInstance("SHA256withECDSA").apply {
            initSign(signer.private)
            update(input.encodeToByteArray())
        }.sign()
        return "$input.${b64(derToJose(der))}~"
    }

    private fun vcIssuerJwks(vararg keys: Pair<String, KeyPair>): JsonObject =
        JsonObject(mapOf("keys" to JsonArray(keys.map { (kid, pair) -> publicJwk(kid, pair.public as ECPublicKey) })))

    private fun publicJwk(kid: String, key: ECPublicKey): JsonObject =
        JsonObject(
            mapOf(
                "kty" to JsonPrimitive("EC"),
                "crv" to JsonPrimitive("P-256"),
                "x" to JsonPrimitive(b64(unsigned(key.w.affineX))),
                "y" to JsonPrimitive(b64(unsigned(key.w.affineY))),
                "kid" to JsonPrimitive(kid),
            ),
        )

    private companion object {
        /** A collaborator the SD-JWT issuer path never calls. */
        inline fun <reified T : Any> unused(): T =
            Proxy.newProxyInstance(T::class.java.classLoader, arrayOf(T::class.java)) { proxy, method, args ->
                when (method.name) {
                    "toString" -> "unused ${T::class.simpleName}"
                    "hashCode" -> System.identityHashCode(proxy)
                    "equals" -> proxy === args?.firstOrNull()
                    else -> error("${T::class.simpleName}.${method.name} must not be called")
                }
            } as T

        const val DID = "did:web:summa.fed.example"
        const val KID = "$DID#issuer-assertion-summa"
        const val OTHER_KID = "$DID#issuer-assertion-other"
        const val ENTITY = "https://summa.fed.example/oid4vci/summa"

        fun ecKeyPair(): KeyPair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

        fun b64(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

        fun unsigned(value: BigInteger): ByteArray {
            val bytes = value.toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
            return ByteArray(32 - bytes.size) + bytes
        }

        /** ASN.1 DER ECDSA signature to the JOSE R || S form. */
        fun derToJose(der: ByteArray): ByteArray {
            var offset = 2
            if (der[1].toInt() and 0x80 != 0) offset += der[1].toInt() and 0x7f
            val rLength = der[offset + 1].toInt()
            val r = BigInteger(1, der.copyOfRange(offset + 2, offset + 2 + rLength))
            offset += 2 + rLength
            val sLength = der[offset + 1].toInt()
            val s = BigInteger(1, der.copyOfRange(offset + 2, offset + 2 + sLength))
            return unsigned(r) + unsigned(s)
        }
    }
}
