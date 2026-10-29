/*
 * Copyright 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

package com.sphereon.wallet.interaction.protocol.oid4vp

import com.sphereon.core.api.encodeToBase64Url
import com.sphereon.oauth2.common.model.AuthorizationRequest
import com.sphereon.openid.oid4vp.common.ClientIdScheme
import com.sphereon.openid.oid4vc.common.CredentialFormat
import com.sphereon.openid.oid4vp.dcql.DcqlCredentialQuery
import com.sphereon.openid.oid4vp.dcql.DcqlQuery
import com.sphereon.openid.oid4vp.dcql.sdJwtVcMeta
import com.sphereon.openid.oid4vp.holder.ResolvedOid4vpRequest
import com.sphereon.openid.oid4vp.holder.SelectedCredential
import com.sphereon.openid.oid4vp.holder.VerifierInfo
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class Oid4vpSdJwtHolderBindingProviderTest {
    @Test
    fun sdJwtCredentialsWithDistinctSubjectsAndBindingKeysProduceIndependentKeyBindings() = runTest {
        val firstKey = """{"kty":"EC","crv":"P-256","x":"first-x","y":"first-y"}"""
        val secondKey = """{"kty":"EC","crv":"P-256","x":"second-x","y":"second-y"}"""
        val wsca = RecordingWsca(publicKeyJwks = mapOf("holder-alias-first" to firstKey, "holder-alias-second" to secondKey))
        val provider = SecureComponentOid4vpSdJwtHolderBindingProvider(wsca)
        val first = SelectedCredential(
            credentialQueryId = "first",
            credentialId = "sdjwt-first",
            presentation = JsonPrimitive(sdJwtCredential("subject-first", firstKey)),
            credentialFormat = CredentialFormat.SD_JWT_VC,
            holderKeyRef = "holder-alias-first",
        )
        val second = first.copy(
            credentialQueryId = "second",
            credentialId = "sdjwt-second",
            presentation = JsonPrimitive(sdJwtCredential("subject-second", secondKey)),
            holderKeyRef = "holder-alias-second",
        )

        val result = provider.applyHolderBinding(
            Oid4vpSdJwtHolderBindingRequest(
                walletUnitId = "wallet-1",
                operationBinding = "attended-operation-1",
                request = sdJwtResolvedRequest(),
                selectedCredentials = listOf(first, second),
            ),
        )

        assertTrue(result.isOk, result.errorOrNull()?.message?.defaultMessage)
        assertEquals(2, wsca.signCalls.size, "each resolved holder binding key requires an independent KB-JWT")
        assertEquals(listOf("holder-alias-first", "holder-alias-second"), wsca.ensureAliases)
        assertEquals(2, result.value.size)
        assertTrue(result.value.all { it.sdJwtKeyBindingApplied })
        assertTrue(result.value[0].presentation != result.value[1].presentation)
    }

    @Test
    fun publicKeyComparisonIgnoresMetadataButRequiresIdenticalEcKeyMaterial() {
        val credentialKey = jwk("""{"kty":"EC","crv":"P-256","x":"x-one","y":"y-one","kid":"issued"}""")
        val sameKey = jwk("""{"kty":"EC","crv":"P-256","x":"x-one","y":"y-one","kid":"runtime","alg":"ES256"}""")
        val differentKey = jwk("""{"kty":"EC","crv":"P-256","x":"x-two","y":"y-two","kid":"issued"}""")

        assertTrue(samePublicKey(credentialKey, sameKey))
        assertFalse(samePublicKey(credentialKey, differentKey))
    }

    @Test
    fun publicKeyComparisonRejectsMissingOrUnsupportedKeyMaterial() {
        assertFalse(samePublicKey(jwk("""{"kty":"EC","crv":"P-256","x":"x"}"""), jwk("""{"kty":"EC","crv":"P-256","x":"x","y":"y"}""")))
        assertFalse(samePublicKey(jwk("""{"kty":"oct","k":"secret"}"""), jwk("""{"kty":"oct","k":"secret"}""")))
    }

    @Test
    fun didJwkCredentialUsesItsEmbeddedPublicKeyForHolderBinding() = runTest {
        val holderKey = """{"kty":"EC","crv":"P-256","x":"holder-x","y":"holder-y"}"""
        val didMethod = "did:jwk:${holderKey.encodeToByteArray().encodeToBase64Url()}#0"
        val wsca = RecordingWsca(publicKeyJwks = mapOf("holder-alias-first" to holderKey))
        val provider = SecureComponentOid4vpSdJwtHolderBindingProvider(wsca)
        val credential = SelectedCredential(
            credentialQueryId = "first",
            credentialId = "sdjwt-did-bound",
            presentation = JsonPrimitive(sdJwtCredentialWithKid(didMethod)),
            credentialFormat = CredentialFormat.SD_JWT_VC,
            holderKeyRef = "holder-alias-first",
        )

        val result = provider.applyHolderBinding(
            Oid4vpSdJwtHolderBindingRequest("wallet-1", "attended-operation-1", sdJwtResolvedRequest(), listOf(credential)),
        )

        assertTrue(result.isOk, result.errorOrNull()?.message?.defaultMessage)
        assertEquals(1, wsca.signCalls.size)
        assertTrue(result.value.single().sdJwtKeyBindingApplied)
    }

    @Test
    fun didJwkHolderBindingRejectsWrongOrMalformedVerificationMethod() = runTest {
        val issuedKey = """{"kty":"EC","crv":"P-256","x":"issued-x","y":"issued-y"}"""
        val runtimeKey = """{"kty":"EC","crv":"P-256","x":"runtime-x","y":"runtime-y"}"""
        val didMethod = "did:jwk:${issuedKey.encodeToByteArray().encodeToBase64Url()}#0"
        val wsca = RecordingWsca(publicKeyJwks = mapOf("holder-alias-first" to runtimeKey))
        val provider = SecureComponentOid4vpSdJwtHolderBindingProvider(wsca)
        suspend fun present(kid: String) = provider.applyHolderBinding(
            Oid4vpSdJwtHolderBindingRequest(
                "wallet-1", "attended-operation-1", sdJwtResolvedRequest(),
                listOf(SelectedCredential("first", "sdjwt-did-bound", JsonPrimitive(sdJwtCredentialWithKid(kid)),
                    credentialFormat = CredentialFormat.SD_JWT_VC, holderKeyRef = "holder-alias-first")),
            ),
        )

        assertEquals("oid4vp.key_binding_key_mismatch", present(didMethod).errorOrNull()?.code)
        assertEquals("oid4vp.key_binding_cnf_jwk_missing", present("did:jwk:invalid#1").errorOrNull()?.code)
        assertTrue(wsca.signCalls.isEmpty())
    }

    private fun jwk(value: String): JsonObject = Json.parseToJsonElement(value) as JsonObject

    private fun sdJwtResolvedRequest() = ResolvedOid4vpRequest(
        request = AuthorizationRequest(clientId = "https://verifier.example/client", nonce = "request-nonce"),
        dcqlQuery = DcqlQuery(
            credentials = listOf(
                DcqlCredentialQuery(id = "first", format = "dc+sd-jwt", meta = sdJwtVcMeta("urn:test:sdjwt")),
                DcqlCredentialQuery(id = "second", format = "dc+sd-jwt", meta = sdJwtVcMeta("urn:test:sdjwt")),
            ),
        ),
        verifierInfo = VerifierInfo(clientId = "https://verifier.example/client", clientIdScheme = ClientIdScheme.REDIRECT_URI),
    )

    private fun sdJwtCredential(subject: String, holderJwk: String): String {
        val header = """{"alg":"ES256","typ":"dc+sd-jwt"}""".encodeToByteArray().encodeToBase64Url()
        val payload = buildJsonObject {
            put("iss", "https://issuer.example")
            put("sub", subject)
            put("cnf", Json.parseToJsonElement("{\"jwk\":$holderJwk}"))
        }.toString().encodeToByteArray().encodeToBase64Url()
        return "$header.$payload.issuer-signature~"
    }

    private fun sdJwtCredentialWithKid(kid: String): String {
        val header = """{"alg":"ES256","typ":"dc+sd-jwt"}""".encodeToByteArray().encodeToBase64Url()
        val payload = buildJsonObject {
            put("iss", "https://issuer.example")
            put("cnf", buildJsonObject { put("kid", kid) })
        }.toString().encodeToByteArray().encodeToBase64Url()
        return "$header.$payload.issuer-signature~"
    }
}
