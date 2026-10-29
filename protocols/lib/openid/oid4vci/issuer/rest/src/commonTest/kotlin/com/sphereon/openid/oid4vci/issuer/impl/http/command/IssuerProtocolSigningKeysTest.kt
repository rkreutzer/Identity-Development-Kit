/* Copyright 2026 Sphereon International B.V. Licensed under the Apache License, Version 2.0. */
package com.sphereon.openid.oid4vci.issuer.impl.http.command

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.error.IdkError
import com.sphereon.openid.oid4vc.common.DisplayProperties
import com.sphereon.openid.oid4vci.common.model.CredentialConfigurationSupported
import com.sphereon.openid.oid4vci.issuer.config.CredentialSigningConfig
import com.sphereon.openid.oid4vci.issuer.config.Oid4vciIssuerConfigProvider
import com.sphereon.openid.oid4vci.issuer.format.SigningKeyMode
import com.sphereon.openid.oid4vci.issuer.impl.signing.IssuerKeyIdResolver
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class IssuerProtocolSigningKeysTest {
    private val publicKey = Json.parseToJsonElement("""{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}""").jsonObject
    private fun config(signing: Map<String, CredentialSigningConfig>, advertised: Set<String> = signing.keys) = object : Oid4vciIssuerConfigProvider {
        override val issuerIdentifier = "https://issuer.example/credentials"
        override val authorizationServers: List<String>? = null
        override val display: List<DisplayProperties>? = null
        override val credentialConfigurations = advertised.associateWith { CredentialConfigurationSupported(format = "dc+sd-jwt") }
        override suspend fun credentialSigningConfigs() = signing
    }
    private fun signing(name: String? = "internal-owned-key", mode: SigningKeyMode = SigningKeyMode.JwkThumbprint) = CredentialSigningConfig(signingKeyAlias = name, signingKeyMode = mode)
    private fun resolver(result: IdkResult<JsonObject, IdkError> = Ok(publicKey), onResolve: (String) -> Unit = {}) = object : IssuerKeyIdResolver {
        override suspend fun resolveDidVerificationMethodId(keyAlias: String, didMethod: String): IdkResult<String, IdkError> = error("DID lookup is not used for thumbprint keys")
        override suspend fun resolvePublicJwk(keyAlias: String): IdkResult<JsonObject, IdkError> { onResolve(keyAlias); return result }
    }

    @Test
    fun publishesOnlyAdvertisedCredentialKeysWithCanonicalThumbprintKids() = runTest {
        val names = mutableListOf<String>()
        val configuration = config(mapOf("selected" to signing(), "not-advertised" to signing("other-key")), setOf("selected"))
        val result = issuerThumbprintSigningJwks(configuration, resolver(onResolve = { names += it })).getOrThrow()!!
        val key = result.getValue("keys").jsonArray.single().jsonObject
        assertEquals(listOf("internal-owned-key"), names)
        assertEquals(JsonPrimitive("sig"), key["use"])
        assertEquals(JsonPrimitive("urn:ietf:params:oauth:jwk-thumbprint:sha-256:oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U"), key["kid"])
        assertEquals(publicKey, JsonObject(key - "kid" - "use"))
        assertTrue(!result.toString().contains("internal-owned-key"))
    }

    @Test
    fun sharedKeyIsPublishedOnceAndUnrelatedSigningModesRemainUnchanged() = runTest {
        val result = issuerThumbprintSigningJwks(config(mapOf("a" to signing(), "b" to signing(), "did" to signing("did-key", SigningKeyMode.Did("web")))), resolver()).getOrThrow()!!
        assertEquals(1, result.getValue("keys").jsonArray.size)
        assertNull(issuerThumbprintSigningJwks(config(mapOf("did" to signing(mode = SigningKeyMode.Did("web")))), null).getOrThrow())
    }

    @Test
    fun refusesMissingBindingsOrUnavailablePublicMaterial() = runTest {
        assertTrue(issuerThumbprintSigningJwks(config(mapOf("a" to signing(null))), resolver()).isErr)
        assertTrue(issuerThumbprintSigningJwks(config(mapOf("a" to signing())), null).isErr)
        assertTrue(issuerThumbprintSigningJwks(config(mapOf("a" to signing())), resolver(Err(IdkError.INVALID_STATE(message = "unavailable")))).isErr)
    }

    @Test
    fun privateAndSymmetricMaterialCannotEnterPublicMetadata() = runTest {
        for (invalid in listOf(JsonObject(publicKey + ("d" to JsonPrimitive("private-value"))), Json.parseToJsonElement("""{"kty":"oct","k":"secret"}""").jsonObject)) {
            val result = issuerThumbprintSigningJwks(config(mapOf("a" to signing())), resolver(Ok(invalid)))
            assertTrue(result.isErr)
            assertTrue(!(result as Err).error.message.defaultMessage.contains("internal-owned-key"))
        }
    }
}
