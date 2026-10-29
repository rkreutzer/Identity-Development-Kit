package com.sphereon.openid.oid4vci.holder

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.decodeFromBase64Url
import com.sphereon.core.api.encodeToBase64Url
import com.sphereon.core.api.encodeToHex
import com.sphereon.core.api.error.IdkError
import com.sphereon.crypto.core.generic.DigestAlg
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.crypto.core.generic.hash
import com.sphereon.crypto.jose.jws.JwsIdentifierMode
import com.sphereon.openid.oid4vci.holder.HolderCredentialProofSigner
import com.sphereon.openid.oid4vci.holder.HolderPreparedSigning
import com.sphereon.openid.oid4vci.holder.HolderSigningRequest
import com.sphereon.openid.oid4vci.holder.impl.CredentialRequestProofPreparationImpl
import com.sphereon.wallet.unit.SecureComponentUsage
import com.sphereon.wallet.unit.WalletAttestedKeyRef
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class CredentialProofPreparationTest {
    @Test
    fun prepareSerializeAndFinalizeUsesFixedIatAndExactSigningBytes() = runTest {
        val signer = PreparationRecordingSigner()
        val preparation = CredentialRequestProofPreparationImpl(signer)
        val request = proofRequest(iatEpochSeconds = 1_700_000_000L)

        val prepared = preparation.prepare(request).getOrElse { error("prepare failed: $it") }
        val restored = Json.decodeFromString<PreparedCredentialRequestProofBatch>(Json.encodeToString(prepared))
        val result = preparation.finalize(restored)

        assertTrue(result.isOk)
        assertEquals(listOf("holder-key-1"), signer.signedKeyIds)
        assertEquals(1_700_000_000L, restored.proofs.single().iatEpochSeconds)
        assertTrue(restored.proofs.single().payloadBase64Url.decodeFromBase64Url().decodeToString().contains("\"iat\":1700000000"))
        assertEquals(
            restored.proofs.single().exactSigningInputBase64Url,
            signer.lastSigningRequest?.signingInput?.let { it.encodeToBase64Url() },
        )
        assertEquals(1, result.value.proofs.proofValues.size)
    }

    @Test
    fun finalizeRejectsMutatedSnapshotBeforeWscaSign() = runTest {
        val signer = PreparationRecordingSigner()
        val preparation = CredentialRequestProofPreparationImpl(signer)
        val prepared = preparation.prepare(proofRequest()).getOrElse { error("prepare failed: $it") }
        val original = prepared.proofs.single()
        val mutations =
            listOf(
                original.copy(exactSigningInputBase64Url = "changed"),
                original.copy(protectedHeaderBase64Url = original.protectedHeaderBase64Url + "x"),
                original.copy(payloadBase64Url = original.payloadBase64Url + "x"),
                original.copy(keyRef = original.keyRef.copy(keyId = "other-key")),
                original.copy(algorithm = "ES384"),
                original.copy(walletUnitId = "other-wallet"),
                original.copy(walletAccountId = "other-account"),
                original.copy(operationBinding = "other-binding"),
                original.copy(operationType = "other-operation-type"),
                original.copy(digestBinding = "sha256:other-digest"),
                original.copy(nonce = "other-nonce"),
                original.copy(audience = "https://other.example"),
            )
        mutations.forEach { mutation ->
            val result = preparation.finalize(prepared.copy(proofs = listOf(mutation)))
            assertTrue(result.isErr)
            assertEquals("ILLEGAL_ARGUMENT_ERROR", result.error.code)
        }
        assertEquals(0, signer.signCalls)
    }

    @Test
    fun batchFinalizePreservesKeyOrderAndUsesDistinctPreparedOperations() = runTest {
        val signer = PreparationRecordingSigner()
        val preparation = CredentialRequestProofPreparationImpl(signer)
        val request = proofRequest(signingKeyIds = listOf("key-a", "key-b"))

        val prepared = preparation.prepare(request).getOrElse { error("prepare failed: $it") }
        val result = preparation.finalize(prepared)

        assertTrue(result.isOk)
        assertEquals(listOf("key-a", "key-b"), signer.signedKeyIds)
        assertEquals(2, signer.signCalls)
        assertEquals(2, prepared.proofs.map { it.keyRef.keyId }.distinct().size)
    }

    @Test
    fun prepareAndFinalizePreservesJoseHeaderPayloadSemantics() = runTest {
        val signer = PreparationRecordingSigner()
        val preparation = CredentialRequestProofPreparationImpl(signer)
        val request = proofRequest(keyInclusionMode = JwsIdentifierMode.JWK.name, keyAttestationJwt = "key-attestation")

        val prepared = preparation.prepare(request).getOrElse { error("prepare failed: $it") }
        val result = preparation.finalize(prepared)
        assertTrue(result.isOk)
        val parts = result.value.proofs.proofValues.single().jsonPrimitive.content.split('.')
        val header = Json.parseToJsonElement(parts[0].decodeFromBase64Url().decodeToString()).jsonObject
        val payload = Json.parseToJsonElement(parts[1].decodeFromBase64Url().decodeToString()).jsonObject

        assertEquals("openid4vci-proof+jwt", header["typ"]?.jsonPrimitive?.content)
        assertEquals("ES256", header["alg"]?.jsonPrimitive?.content)
        assertTrue(header["jwk"]?.jsonObject != null)
        assertEquals("key-attestation", header["key_attestation"]?.jsonPrimitive?.content)
        assertEquals("https://issuer.example", payload["aud"]?.jsonPrimitive?.content)
        assertEquals("1700000001", payload["iat"]?.jsonPrimitive?.content)
        assertEquals("c_nonce-1", payload["nonce"]?.jsonPrimitive?.content)
        assertEquals("client-1", payload["iss"]?.jsonPrimitive?.content)
    }

    @Test
    fun blankKeyAttestationIsNormalizedAwayBeforeJoseConstruction() = runTest {
        val signer = PreparationRecordingSigner()
        val preparation = CredentialRequestProofPreparationImpl(signer)

        val prepared = preparation.prepare(proofRequest(keyAttestationJwt = " \t")).getOrElse { error("prepare failed: $it") }
        val snapshot = prepared.proofs.single()
        val header = snapshot.headerObject()
        val result = preparation.finalize(prepared)

        assertTrue(result.isOk)
        assertNull(snapshot.keyAttestationJwt)
        assertFalse(header.containsKey("key_attestation"))
        assertEquals(1, signer.signCalls)
    }

    @Test
    fun joseClaimsRejectNullWrongTypesUnexpectedPresenceAndMissingMembersBeforeWsca() = runTest {
        val signer = PreparationRecordingSigner()
        val preparation = CredentialRequestProofPreparationImpl(signer)
        val complete = preparation.prepare(proofRequest(keyAttestationJwt = "key-attestation")).getOrElse { error("prepare failed: $it") }
        val original = complete.proofs.single()
        val originalHeader = original.headerObject()
        val originalPayload = original.payloadObject()
        val completeMutations =
            listOf(
                original.withJose(payload = originalPayload.withMember("nonce", JsonNull)),
                original.withJose(payload = originalPayload.withMember("nonce", JsonPrimitive(7))),
                original.withJose(payload = originalPayload.withMember("nonce", buildJsonObject { put("value", JsonPrimitive("nonce")) })),
                original.withJose(payload = originalPayload.withMember("nonce", JsonArray(listOf(JsonPrimitive("nonce"))))),
                original.withJose(payload = originalPayload.withoutMember("nonce")),
                original.withJose(payload = originalPayload.withMember("iss", JsonNull)),
                original.withJose(payload = originalPayload.withMember("iss", JsonPrimitive(true))),
                original.withJose(payload = originalPayload.withMember("iss", buildJsonObject { put("value", JsonPrimitive("client-1")) })),
                original.withJose(payload = originalPayload.withoutMember("iss")),
                original.withJose(header = originalHeader.withMember("key_attestation", JsonNull)),
                original.withJose(header = originalHeader.withMember("key_attestation", JsonPrimitive(7))),
                original.withJose(header = originalHeader.withMember("key_attestation", JsonArray(listOf(JsonPrimitive("attestation"))))),
                original.withJose(header = originalHeader.withoutMember("key_attestation")),
            )

        val noOptionalClaims =
            preparation.prepare(proofRequest(cNonce = null, clientId = null, keyAttestationJwt = null)).getOrElse { error("prepare failed: $it") }
        val absentClaims = noOptionalClaims.proofs.single()
        val absentHeader = absentClaims.headerObject()
        val absentPayload = absentClaims.payloadObject()
        val unexpectedPresence =
            listOf(
                absentClaims.withJose(payload = absentPayload.withMember("nonce", JsonPrimitive("unexpected"))),
                absentClaims.withJose(payload = absentPayload.withMember("iss", JsonPrimitive("unexpected"))),
                absentClaims.withJose(header = absentHeader.withMember("key_attestation", JsonPrimitive("unexpected"))),
            )

        (completeMutations + unexpectedPresence).forEach { mutation ->
            val result = preparation.finalize(PreparedCredentialRequestProofBatch(listOf(mutation)))
            assertTrue(result.isErr)
            assertEquals("ILLEGAL_ARGUMENT_ERROR", result.error.code)
        }
        assertEquals(2, signer.prepareCalls, "claim mutations must be rejected before holder-signer re-preparation")
        assertEquals(0, signer.signCalls, "claim mutations must be rejected before signing")
    }

    @Test
    fun malformedAndNonObjectJoseSegmentsNeverReachWsca() = runTest {
        val signer = PreparationRecordingSigner()
        val preparation = CredentialRequestProofPreparationImpl(signer)
        val prepared = preparation.prepare(proofRequest()).getOrElse { error("prepare failed: $it") }
        val original = prepared.proofs.single()
        val malformed =
            listOf(
                original.copy(protectedHeaderBase64Url = "").withIntegrity(),
                original.copy(payloadBase64Url = "").withIntegrity(),
                original.copy(protectedHeaderBase64Url = "W10").withIntegrity(), // []
                original.copy(payloadBase64Url = "W10").withIntegrity(), // []
                original.copy(protectedHeaderBase64Url = "not-base64").withIntegrity(),
            )

        malformed.forEach { mutation ->
            val result = preparation.finalize(prepared.copy(proofs = listOf(mutation)))
            assertTrue(result.isErr)
        }
        assertEquals(1, signer.prepareCalls, "malformed snapshots must not trigger re-preparation")
        assertEquals(0, signer.signCalls, "malformed snapshots must not trigger signing")
    }

    private fun PreparedCredentialRequestProof.withIntegrity(): PreparedCredentialRequestProof {
        val json = Json { encodeDefaults = false; explicitNulls = false }
        return copy(
            integrityBinding =
                "sha256:${hash(
                    json.encodeToString(PreparedCredentialRequestProof.serializer(), copy(integrityBinding = "pending")).encodeToByteArray(),
                    DigestAlg.SHA256,
                ).encodeToHex()}",
        )
    }

    private fun PreparedCredentialRequestProof.headerObject(): JsonObject =
        Json.parseToJsonElement(protectedHeaderBase64Url.decodeFromBase64Url().decodeToString()).jsonObject

    private fun PreparedCredentialRequestProof.payloadObject(): JsonObject =
        Json.parseToJsonElement(payloadBase64Url.decodeFromBase64Url().decodeToString()).jsonObject

    private fun PreparedCredentialRequestProof.withJose(
        header: JsonObject = headerObject(),
        payload: JsonObject = payloadObject(),
    ): PreparedCredentialRequestProof {
        val protectedHeader = header.toString().encodeToByteArray().encodeToBase64Url()
        val encodedPayload = payload.toString().encodeToByteArray().encodeToBase64Url()
        return copy(
            protectedHeaderBase64Url = protectedHeader,
            payloadBase64Url = encodedPayload,
            exactSigningInputBase64Url = "$protectedHeader.$encodedPayload".encodeToByteArray().encodeToBase64Url(),
        ).withIntegrity()
    }

    private fun JsonObject.withMember(name: String, value: JsonElement): JsonObject =
        buildJsonObject {
            forEach { (key, element) -> put(key, element) }
            put(name, value)
        }

    private fun JsonObject.withoutMember(name: String): JsonObject =
        buildJsonObject {
            forEach { (key, element) -> if (key != name) put(key, element) }
        }

    // OID4VCI 1.0 Appendix F.1: a DID-bound proof's kid is a DID URL of the key. did:jwk encodes the
    // public JWK itself and its only verification method is #0; private JWKs must be rejected.
    @Test
    fun didJwkVerificationMethodOfTheSigningKeyBecomesTheProofKid() = runTest {
        val signer = PreparationRecordingSigner()
        val preparation = CredentialRequestProofPreparationImpl(signer)
        val request = proofRequest(keyInclusionMode = JwsIdentifierMode.DID.name, holderDidVerificationMethod = SIGNING_KEY_DID_JWK_VM)

        val prepared = preparation.prepare(request).getOrElse { error("prepare failed: $it") }
        val header = prepared.proofs.single().headerObject()
        val result = preparation.finalize(Json.decodeFromString<PreparedCredentialRequestProofBatch>(Json.encodeToString(prepared)))

        assertTrue(result.isOk, "finalize failed: ${if (result.isErr) result.error.message.defaultMessage else ""}")
        assertEquals(SIGNING_KEY_DID_JWK_VM, header["kid"]?.jsonPrimitive?.content)
        assertFalse(header.containsKey("jwk"), "kid and jwk are mutually exclusive (Appendix F.1)")
        assertEquals(SIGNING_KEY_DID_JWK_VM, prepared.proofs.single().holderDidVerificationMethod)
        assertEquals(1, signer.signCalls)
    }

    // RFC 7638: the same key may be serialized with optional members (kid/alg/use) or in another
    // member order; the did:jwk names the signing key whenever the thumbprints agree.
    @Test
    fun aDidJwkOfTheSameKeyWithOtherOptionalMembersOrOrderStillNamesTheSigningKey() = runTest {
        val signer = PreparationRecordingSigner(
            publicKeyJwk = """{"kty":"EC","crv":"P-256","x":"AQ","y":"Ag","kid":"wsca-key-1","alg":"ES256","use":"sig"}""",
        )
        listOf(
            SIGNING_KEY_DID_JWK_VM,
            didJwk("""{"y":"Ag","x":"AQ","crv":"P-256","kty":"EC"}""") + "#0",
            didJwk("""{"kty":"EC","crv":"P-256","x":"AQ","y":"Ag","use":"sig"}""") + "#0",
        ).forEach { verificationMethod ->
            val prepared = CredentialRequestProofPreparationImpl(signer)
                .prepare(proofRequest(keyInclusionMode = JwsIdentifierMode.DID.name, holderDidVerificationMethod = verificationMethod))

            assertTrue(prepared.isOk, "$verificationMethod names the same key")
            assertEquals(verificationMethod, prepared.value.proofs.single().headerObject()["kid"]?.jsonPrimitive?.content)
        }
    }

    @Test
    fun prepareRefusesADidVerificationMethodThatIsNotTheSigningKeysDidJwk() = runTest {
        val otherKey = didJwk("""{"kty":"EC","crv":"P-256","x":"Aw","y":"BA"}""")
        val privateKey = didJwk("""{"kty":"EC","crv":"P-256","x":"AQ","y":"Ag","d":"BQ"}""")
        listOf(
            "$otherKey#0",
            "${SIGNING_KEY_DID_JWK_VM.substringBefore('#')}#1",
            SIGNING_KEY_DID_JWK_VM.substringBefore('#'),
            "did:example:holder#0",
            "$privateKey#0",
        ).forEach { verificationMethod ->
            val signer = PreparationRecordingSigner()
            val result = CredentialRequestProofPreparationImpl(signer)
                .prepare(proofRequest(keyInclusionMode = JwsIdentifierMode.DID.name, holderDidVerificationMethod = verificationMethod))

            assertTrue(result.isErr, "$verificationMethod must be refused")
            assertEquals(0, signer.prepareCalls)
            assertEquals(0, signer.signCalls)
        }
    }

    @Test
    fun anExplicitDidVerificationMethodRequiresDidModeAndOneSigningKey() {
        assertFailsWith<IllegalArgumentException> {
            proofRequest(keyInclusionMode = JwsIdentifierMode.JWK.name, holderDidVerificationMethod = SIGNING_KEY_DID_JWK_VM)
        }
        assertFailsWith<IllegalArgumentException> {
            proofRequest(
                keyInclusionMode = JwsIdentifierMode.DID.name,
                signingKeyIds = listOf("key-a", "key-b"),
                holderDidVerificationMethod = SIGNING_KEY_DID_JWK_VM,
            )
        }
    }

    @Test
    fun finalizeRejectsASnapshotWhoseDidVerificationMethodNamesAnotherKey() = runTest {
        val signer = PreparationRecordingSigner()
        val preparation = CredentialRequestProofPreparationImpl(signer)
        val prepared = preparation
            .prepare(proofRequest(keyInclusionMode = JwsIdentifierMode.DID.name, holderDidVerificationMethod = SIGNING_KEY_DID_JWK_VM))
            .getOrElse { error("prepare failed: $it") }
        val original = prepared.proofs.single()
        val swapped = "${didJwk("""{"kty":"EC","crv":"P-256","x":"Aw","y":"BA"}""")}#0"
        val mutation = original
            .copy(holderDidVerificationMethod = swapped)
            .withJose(header = original.headerObject().withMember("kid", JsonPrimitive(swapped)))

        val result = preparation.finalize(prepared.copy(proofs = listOf(mutation)))

        assertTrue(result.isErr)
        assertEquals("ILLEGAL_ARGUMENT_ERROR", result.error.code)
        assertEquals(0, signer.signCalls)
    }

    private fun proofRequest(
        iatEpochSeconds: Long = 1_700_000_001L,
        signingKeyIds: List<String> = listOf("holder-key-1"),
        keyInclusionMode: String = JwsIdentifierMode.KID.name,
        keyAttestationJwt: String? = null,
        cNonce: String? = "c_nonce-1",
        clientId: String? = "client-1",
        holderDidVerificationMethod: String? = null,
    ) =
        CredentialRequestProofPreparationRequest(
            walletUnitId = "wallet-unit-1",
            operationBinding = "credential-request-1",
            issuerUrl = "https://issuer.example",
            cNonce = cNonce,
            signingKeyIds = signingKeyIds,
            signingAlgorithm = "ES256",
            clientId = clientId,
            keyInclusionMode = keyInclusionMode,
            keyAttestationJwt = keyAttestationJwt,
            iatEpochSeconds = iatEpochSeconds,
            holderDidVerificationMethod = holderDidVerificationMethod,
        )
}

/** did:jwk method-specific id: base64url of the UTF-8 JWK JSON. */
private fun didJwk(publicJwkJson: String): String = "did:jwk:" + publicJwkJson.encodeToByteArray().encodeToBase64Url()

/** The #0 verification method of the recording signer's public JWK. */
private val SIGNING_KEY_DID_JWK_VM = didJwk("""{"kty":"EC","crv":"P-256","x":"AQ","y":"Ag"}""") + "#0"

private class PreparationRecordingSigner(
    private val publicKeyJwk: String = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"AQ\",\"y\":\"Ag\"}",
) : HolderCredentialProofSigner {
    var signCalls = 0
    var prepareCalls = 0
    val signedKeyIds = mutableListOf<String>()
    var lastSigningRequest: HolderSigningRequest? = null

    override suspend fun ensureKey(walletUnitId: String, usage: SecureComponentUsage, algorithm: SignatureAlgorithm, keyAlias: String?): IdkResult<WalletAttestedKeyRef, IdkError> =
        Ok(
            WalletAttestedKeyRef(
                keyAlias ?: "key",
                "ES256",
                publicKeyJwk = publicKeyJwk,
                keyRef = keyAlias,
                walletUnitId = walletUnitId,
            ),
        )

    override suspend fun prepareSign(request: HolderSigningRequest): IdkResult<HolderPreparedSigning, IdkError> =
        Ok(
            HolderPreparedSigning(
                walletUnitId = request.walletUnitId,
                keyRef = request.keyRef,
                walletAccountId = request.walletAccountId,
                operationBinding = request.operationBinding,
                operationType = "wallet.holder.test.sign",
                digestBinding = "digest:${request.keyRef.keyId}:${request.signingInput.decodeToString()}",
                nonce = request.nonce ?: "nonce-${request.keyRef.keyId}",
                audience = request.audience ?: error("audience required"),
                signingInput = request.signingInput,
            ),
        ).also { prepareCalls++ }

    override suspend fun sign(prepared: HolderPreparedSigning, request: HolderSigningRequest): IdkResult<ByteArray, IdkError> {
        signCalls++
        signedKeyIds += request.keyRef.keyId
        lastSigningRequest = request
        return Ok(byteArrayOf(1, 2, 3))
    }
}
