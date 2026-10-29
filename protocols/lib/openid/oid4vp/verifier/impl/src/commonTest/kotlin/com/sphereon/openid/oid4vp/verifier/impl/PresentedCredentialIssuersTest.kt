/*
 * Copyright 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

package com.sphereon.openid.oid4vp.verifier.impl

import com.sphereon.core.api.Err
import com.sphereon.core.api.Ok
import com.sphereon.core.api.encodeToBase64Url
import com.sphereon.core.api.error.IdkError
import com.sphereon.crypto.resolution.extern.ExternalIdentifierX5cOpts
import com.sphereon.openid.oid4vp.verifier.CredentialIssuerAuthenticationLookup
import com.sphereon.openid.oid4vp.verifier.CredentialIssuerControllerClaim
import com.sphereon.openid.oid4vp.verifier.TrustedAuthenticationPurpose
import com.sphereon.openid.oid4vp.verifier.TrustedAuthenticationResolution
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class PresentedCredentialIssuersTest {
    private fun jwt(payload: String) =
        "${"""{"alg":"ES256"}""".encodeToByteArray().encodeToBase64Url()}.${payload.encodeToByteArray().encodeToBase64Url()}.c2ln"

    private val jwks = Json.parseToJsonElement(
        """{"keys":[{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","kid":"k1"}]}""",
    ).jsonObject

    private fun admitted(controller: String, purpose: TrustedAuthenticationPurpose = TrustedAuthenticationPurpose.CREDENTIAL_ISSUER) =
        TrustedAuthenticationResolution(controller, trustedJwks = jwks, purpose = purpose)

    @Test
    fun collectsHttpsIssuersOfSdJwtCompactCredentialsAndPresentationChildren() {
        val sdJwt = jwt("""{"iss":"https://issuer-a.example","vct":"t"}""") + "~disclosure~"
        val child = jwt("""{"iss":"https://issuer-c.example","vc":{"issuer":"https://issuer-c.example"}}""")
        val presentation = jwt("""{"iss":"did:example:holder","vp":{"verifiableCredential":["$child",{"id":"data:application/vc+jwt,${jwt("""{"vc":{"issuer":{"id":"https://issuer-d.example"}}}""")}"}]}}""")
        val issuers = PresentedCredentialIssuers.collect(
            listOf(
                JsonPrimitive(sdJwt),
                JsonPrimitive(jwt("""{"iss":"did:example:issuer"}""")),
                JsonPrimitive(jwt("""{"iss":"http://insecure.example"}""")),
                JsonPrimitive(presentation),
                Json.parseToJsonElement("""{"issuer":"https://ldp.example"}"""),
            ),
        )
        assertEquals(listOf("https://issuer-a.example", "https://issuer-c.example", "https://issuer-d.example"), issuers)
    }

    @Test
    fun resolvesOnlyUnconfiguredIssuersAndKeepsOnlyExactAdmittedMaterial() = runTest {
        val looked = mutableListOf<String>()
        val lookup = CredentialIssuerAuthenticationLookup { issuer ->
            looked += issuer
            when (issuer) {
                "https://admitted.example" -> Ok(admitted(issuer))
                "https://other-controller.example" -> Ok(admitted("https://someone-else.example"))
                "https://holder-purpose.example" -> Ok(admitted(issuer, TrustedAuthenticationPurpose.HOLDER))
                "https://failing.example" -> Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "refused"))
                // X.509 material would also count as an mdoc status root for every credential; refused on demand.
                "https://x509.example" -> Ok(TrustedAuthenticationResolution(issuer, ExternalIdentifierX5cOpts(listOf("root")), purpose = TrustedAuthenticationPurpose.CREDENTIAL_ISSUER))
                else -> Ok(null)
            }
        }
        val presentations = listOf(
            "https://configured.example", "https://admitted.example", "https://other-controller.example",
            "https://holder-purpose.example", "https://failing.example", "https://x509.example", "https://unknown.example",
        ).map { JsonPrimitive(jwt("""{"iss":"$it"}""")) }

        val resolved = PresentedCredentialIssuers.resolve(presentations, listOf(admitted("https://configured.example")), lookup)

        assertEquals(listOf("https://admitted.example"), resolved.map { it.controller })
        assertEquals(null, mdocStatusTrustAnchors(resolved))
        assertTrue("https://configured.example" !in looked)
    }

    @Test
    fun collectsFederationEntitiesNamedByDidIssuedCredentials() {
        val entity = "https://summa.fed.example/oid4vci/summa"
        val sdJwt = jwt("""{"iss":"did:web:summa.fed.example","fed":"$entity","vct":"t"}""") + "~"
        val vcdm11 = jwt("""{"iss":"did:web:other.example","vc":{"issuer":"did:web:other.example","termsOfUse":{"type":"OpenIDFederation","policyId":"https://other.fed.example"}}}""")
        val vcdm2 = jwt("""{"iss":"did:jwk:abc","termsOfUse":[{"type":"OtherPolicy","id":"x"},{"type":"OpenIDFederation","policyId":"$entity"}]}""")
        val entities = PresentedCredentialIssuers.collectFederationEntities(
            listOf(
                JsonPrimitive(sdJwt),
                JsonPrimitive(vcdm11),
                JsonPrimitive(vcdm2),
                // An https issuer is resolved as itself; malformed, insecure or conflicting entities select nothing.
                JsonPrimitive(jwt("""{"iss":"https://issuer.example","fed":"https://ignored.example"}""")),
                JsonPrimitive(jwt("""{"iss":"did:web:a.example","fed":"http://insecure.example"}""")),
                JsonPrimitive(jwt("""{"iss":"did:web:b.example","fed":"https://x.example#frag"}""")),
                JsonPrimitive(jwt("""{"iss":"did:web:c.example","fed":42}""")),
                JsonPrimitive(jwt("""{"iss":"did:web:d.example","fed":"https://one.example","termsOfUse":{"type":"OpenIDFederation","policyId":"https://two.example"}}""")),
            ),
        )
        assertEquals(
            mapOf(
                entity to setOf("did:web:summa.fed.example", "did:jwk:abc"),
                "https://other.fed.example" to setOf("did:web:other.example"),
            ),
            entities,
        )
    }

    @Test
    fun resolvesFederationEntitiesOnlyAsAdmittedFederationEntityMaterial() = runTest {
        val looked = mutableListOf<String>()
        val lookup = object : CredentialIssuerAuthenticationLookup {
            override suspend fun resolve(issuer: String) = error("no https issuer is presented")

            override suspend fun resolveFederationEntity(entityIdentifier: String): com.sphereon.core.api.IdkResult<TrustedAuthenticationResolution?, IdkError> {
                looked += entityIdentifier
                return when (entityIdentifier) {
                    "https://admitted.example" -> Ok(federationEntity(entityIdentifier))
                    // Ordinary issuer material for the entity, or material for another entity, is refused.
                    "https://issuer-claim.example" -> Ok(admitted(entityIdentifier))
                    "https://other-controller.example" -> Ok(federationEntity("https://someone-else.example"))
                    "https://failing.example" -> Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "refused"))
                    else -> Ok(null)
                }
            }
        }
        val presentations = listOf(
            "https://admitted.example", "https://issuer-claim.example", "https://other-controller.example",
            "https://failing.example", "https://unknown.example", "https://configured.example", "https://did-admitted.example",
        ).mapIndexed { index, entity ->
            val did = if (entity == "https://did-admitted.example") "did:web:admitted-did.example" else "did:web:issuer-$index.example"
            JsonPrimitive(jwt("""{"iss":"$did","fed":"$entity"}"""))
        }
        val existing = listOf(federationEntity("https://configured.example"), admitted("did:web:admitted-did.example"))

        val resolved = PresentedCredentialIssuers.resolve(presentations, existing, lookup)

        assertEquals(listOf("https://admitted.example"), resolved.map { it.controller })
        assertEquals(CredentialIssuerControllerClaim.FEDERATION_ENTITY, resolved.single().controllerClaim)
        assertTrue("https://configured.example" !in looked, "an already admitted entity is not resolved again")
        assertTrue("https://did-admitted.example" !in looked, "a DID admitted directly keeps its own admission")
    }

    @Test
    fun federationEntityMaterialMustBeCredentialIssuerJwks() {
        assertFailsWith<IllegalArgumentException> {
            TrustedAuthenticationResolution(
                "https://entity.example",
                trustedJwks = jwks,
                purpose = TrustedAuthenticationPurpose.HOLDER,
                controllerClaim = CredentialIssuerControllerClaim.FEDERATION_ENTITY,
            )
        }
        assertFailsWith<IllegalArgumentException> {
            TrustedAuthenticationResolution(
                "https://entity.example",
                identifier = ExternalIdentifierX5cOpts(listOf("root")),
                purpose = TrustedAuthenticationPurpose.CREDENTIAL_ISSUER,
                controllerClaim = CredentialIssuerControllerClaim.FEDERATION_ENTITY,
            )
        }
    }

    private fun federationEntity(controller: String) =
        TrustedAuthenticationResolution(
            controller,
            trustedJwks = jwks,
            purpose = TrustedAuthenticationPurpose.CREDENTIAL_ISSUER,
            controllerClaim = CredentialIssuerControllerClaim.FEDERATION_ENTITY,
        )

    @Test
    fun boundsTheNumberOfLookedUpIssuers() {
        val presentations = (1..40).map { JsonPrimitive(jwt("""{"iss":"https://issuer-$it.example"}""")) }
        assertEquals(PresentedCredentialIssuers.MAX_ISSUERS, PresentedCredentialIssuers.collect(presentations).size)
    }
}
