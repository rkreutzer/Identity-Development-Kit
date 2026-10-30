/*
 * © 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.sphereon.openid.oid4vci.issuer.impl.format

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.encodeToBase64Url
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.error.sourceAs
import com.sphereon.crypto.core.interop.getPublicKeyJwk
import com.sphereon.crypto.jose.jws.JwsJsonFlattened
import com.sphereon.crypto.jose.jws.JwsJsonGeneral
import com.sphereon.crypto.jose.jws.JwsValidationResult
import com.sphereon.crypto.jose.jws.JwtCompactResult
import com.sphereon.crypto.jose.jws.JwtService
import com.sphereon.crypto.jose.jws.PreparedJwsObject
import com.sphereon.crypto.jose.jws.command.CreateJwsArgs
import com.sphereon.crypto.jose.jws.command.CreateJwsJsonArgs
import com.sphereon.crypto.jose.jws.command.VerifyJwsArgs
import com.sphereon.crypto.core.jose.JwaCurve
import com.sphereon.crypto.core.jose.JwaKeyType
import com.sphereon.crypto.core.jose.Jwk
import com.sphereon.crypto.core.jose.generateJwkThumbprintUri
import com.sphereon.crypto.core.x509.certificateChainFromPem
import com.sphereon.jsonld.LinkedDataDocument
import com.sphereon.jsonld.command.JsonLdContextValidator
import com.sphereon.jsonld.command.JsonLdSchemaValidator
import com.sphereon.jsonld.command.MapBackedJsonLdSchemaRegistry
import com.sphereon.jsonld.command.jsonLdSchemaEntry
import com.sphereon.jsonld.loader.LinkedDataDocumentLoader
import com.sphereon.openid.oid4vc.common.CredentialFormat
import com.sphereon.openid.oid4vc.common.vcdm.VcdmError
import com.sphereon.openid.oid4vc.common.vcdm.VcdmProfiles
import com.sphereon.openid.oid4vci.common.model.CredentialConfigurationSupported
import com.sphereon.openid.oid4vci.common.model.CredentialDefinition
import com.sphereon.openid.oid4vci.common.model.CredentialRequest
import com.sphereon.openid.oid4vci.issuer.format.IssuanceContext
import com.sphereon.openid.oid4vci.issuer.format.SigningKeyMode
import com.sphereon.openid.oid4vci.issuer.impl.signing.IssuerKeyIdResolver
import com.sphereon.statuslist.StatusListBinding
import com.sphereon.statuslist.StatusListSpec
import com.sphereon.statuslist.spi.CredentialStatusEnricher
import com.sphereon.statuslist.spi.ReservedStatus
import com.sphereon.statuslist.spi.StatusClaimMergeTarget
import com.sphereon.statuslist.spi.StatusEnrichmentContext
import com.sphereon.statuslist.spi.StatusReservationHandle
import dev.zacsweers.metro.Provider
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.long
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Instant

private val x5cFallbackCertificatePem =
    """
-----BEGIN CERTIFICATE-----
MIIB3DCCAYMCFA6bjsh9CB8NbtINaWK8WNgBMx2iMAoGCCqGSM49BAMCMHExCzAJ
BgNVBAYTAk5MMRYwFAYDVQQIDA1Ob3J0aCBIb2xsYW5kMRIwEAYDVQQHDAlBbXN0
ZXJkYW0xDjAMBgNVBAoMBU15T3JnMQswCQYDVQQLDAJJRDEZMBcGA1UEAwwQdGVz
dC5leGFtcGxlLmNvbTAeFw0yNTA1MDEwOTE5NDFaFw0yNjA1MDEwOTE5NDFaMHEx
CzAJBgNVBAYTAk5MMRYwFAYDVQQIDA1Ob3J0aCBIb2xsYW5kMRIwEAYDVQQHDAlB
bXN0ZXJkYW0xDjAMBgNVBAoMBU15T3JnMQswCQYDVQQLDAJJRDEZMBcGA1UEAwwQ
dGVzdC5leGFtcGxlLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABP7W2xjU
4raapzyctjNDkRLGHP7RgAtVqAHRnS5LWz2oXhgKHyhCcwlLrfCOCEIHta+gajwz
2mxZ8j6ix1SNXvkwCgYIKoZIzj0EAwIDRwAwRAIgF9E2jWW+qMnmL3qpB5VvJ/8J
e/K96UVYWQ2T23OA1SYCIAaD8LNo+RgwA0rE7wKKOrogIfQUy+qFPVKjmcDTcHln
-----END CERTIFICATE-----
    """.trimIndent()

class VcLdJsonJwtFormatHandlerTest {
    private val vcdm2Body =
        buildJsonObject {
            put("@context", buildJsonObject { put("name", JsonPrimitive("https://schema.org/name")) })
        }
    private val untpBody =
        buildJsonObject {
            put("@context", buildJsonObject { put("description", JsonPrimitive("https://schema.org/description")) })
        }
    private val bundleLoader =
        LinkedDataDocumentLoader { iri ->
            when (iri) {
                "https://www.w3.org/ns/credentials/v2" -> {
                    Ok(
                        LinkedDataDocument(
                            documentUrl = iri,
                            content = vcdm2Body,
                            contentType = "application/ld+json",
                        ),
                    )
                }

                "https://vocabulary.uncefact.org/untp/" -> {
                    Ok(
                        LinkedDataDocument(
                            documentUrl = iri,
                            content = untpBody,
                            contentType = "application/ld+json",
                        ),
                    )
                }

                else -> {
                    Err(
                        com.sphereon.jsonld.JsonLdError.LoadingDocumentFailed(
                            iri = iri,
                            reason = "no fixture for $iri",
                        ),
                    )
                }
            }
        }

    private val widgetSchema =
        buildJsonObject {
            put("\$schema", JsonPrimitive("https://json-schema.org/draft/2020-12/schema"))
            put("type", JsonPrimitive("object"))
        }

    private val schemaRegistry =
        MapBackedJsonLdSchemaRegistry(
            mapOf(
                "DigitalProductPassport" to
                    jsonLdSchemaEntry(
                        schemaUri = "https://test.example/dpp.json",
                        schema = widgetSchema,
                    ),
            ),
        )

    private fun newHandler(
        capturedPayload: ((JsonObject) -> Unit)? = null,
        kms: TestKmsMock = TestKmsMock(),
        issuerKeyIdResolver: IssuerKeyIdResolver = StubIssuerKeyIdResolver,
        statusEnricher: CredentialStatusEnricher? = null,
    ): VcLdJsonJwtFormatHandler =
        VcLdJsonJwtFormatHandler(
            signatureService = (FakeJwtService(capturedPayload)).asSignatureServiceFixture(),
            kms = kms,
            issuerKeyIdResolver = issuerKeyIdResolver,
            contextValidator = JsonLdContextValidator(bundleLoader),
            schemaValidator = JsonLdSchemaValidator(schemaRegistry),
            statusEnricherProvider = statusEnricher?.let { Provider { it } },
        )

    private fun makeContext(
        types: List<String>?,
        attributes: Map<String, JsonElement> = mapOf("name" to JsonPrimitive("Alice")),
        extraContexts: List<String>? = listOf("https://vocabulary.uncefact.org/untp/"),
    ) = IssuanceContext(
        subject = "did:example:holder123",
        clientId = "client-1",
        issuerIdentifier = "https://issuer.example.com",
        credentialConfigurationId = "untp-dpp",
        credentialConfiguration =
            CredentialConfigurationSupported(
                format = CredentialFormat.JWT_VC_JSON_LD.value,
                credentialDefinition = CredentialDefinition(type = types, context = extraContexts),
            ),
        holderBindingKey = null,
        attributes = attributes,
        signingKeyAlias = "issuer-signing-untp",
    )

    @Test
    fun canHandleReturnsTrueForVcLdJsonJwt() =
        runTest {
            val handler = newHandler()
            val request = CredentialRequest(format = CredentialFormat.JWT_VC_JSON_LD.value)
            assertTrue(
                handler.canHandle(
                    request,
                    CredentialConfigurationSupported(format = CredentialFormat.JWT_VC_JSON_LD.value),
                ),
            )
        }

    @Test
    fun canHandleReturnsFalseForJwtVcJson() =
        runTest {
            val handler = newHandler()
            val request = CredentialRequest(format = CredentialFormat.JWT_VC_JSON.value)
            assertFalse(
                handler.canHandle(
                    request,
                    CredentialConfigurationSupported(format = CredentialFormat.JWT_VC_JSON.value),
                ),
            )
        }

    @Test
    fun issueCredentialBuildsVcdm2BodyWithUntpContext() =
        runTest {
            var captured: JsonObject? = null
            val handler = newHandler(capturedPayload = { captured = it })
            val request = CredentialRequest(format = CredentialFormat.JWT_VC_JSON_LD.value)
            val context =
                makeContext(
                    types = listOf("VerifiableCredential", "DigitalProductPassport"),
                    attributes =
                        mapOf(
                            "productName" to JsonPrimitive("Sample Widget"),
                            "weightKg" to JsonPrimitive(2.5),
                        ),
                )

            val result = handler.issueCredential(request, context)
            assertTrue(result.isOk, "issuance must succeed: ${if (result.isErr) result.error else ""}")
            assertEquals(CredentialFormat.JWT_VC_JSON_LD.value, result.value.format)

            val payload = assertNotNull(captured, "JwtService must have been invoked")

            // VC body fields are at the JWT root (no `vc` wrapper, per VC-JOSE-COSE §3.1.1).
            val contexts =
                payload["@context"]?.jsonArray
                    ?: error("@context must be present at root")
            assertEquals(
                listOf("https://www.w3.org/ns/credentials/v2", "https://vocabulary.uncefact.org/untp/"),
                contexts.map { it.jsonPrimitive.content },
            )

            val types = payload["type"]?.jsonArray ?: error("type must be present")
            assertEquals(
                listOf("VerifiableCredential", "DigitalProductPassport"),
                types.map { it.jsonPrimitive.content },
            )

            // VCDM 2.0 uses validFrom (not issuanceDate).
            assertNotNull(payload["validFrom"])
            assertEquals(
                "https://issuer.example.com",
                payload["issuer"]?.jsonPrimitive?.content,
            )

            // JWT registered claims are at the same level.
            assertEquals("https://issuer.example.com", payload["iss"]?.jsonPrimitive?.content)
            assertNull(payload["sub"], "VCDM 2.0 jwt_vc_json-ld must not derive sub from proof/issuance subject")
            assertNotNull(payload["iat"])
            assertTrue(payload["nbf"] == null, "VCDM 2.0 issuance must not emit the discouraged nbf claim")

            // Custom attributes flow into credentialSubject, not the root.
            val cs = payload["credentialSubject"]?.jsonObject ?: error("credentialSubject")
            assertEquals("Sample Widget", cs["productName"]?.jsonPrimitive?.content)
        }

    @Test
    fun federationEntityIssuerAddsOpenIdFederationTermsOfUse() =
        runTest {
            var captured: JsonObject? = null
            val result =
                newHandler(capturedPayload = { captured = it }).issueCredential(
                    request = CredentialRequest(format = CredentialFormat.JWT_VC_JSON_LD.value),
                    context = makeContext(types = listOf("VerifiableCredential", "DigitalProductPassport")).copy(
                        federationEntityIdentifier = "https://issuer.example.com",
                    ),
                )

            assertTrue(result.isOk, "issuance must succeed: ${if (result.isErr) result.error else ""}")
            val payload = assertNotNull(captured)
            // DIIP v5 Appendix B: type OpenIDFederation, policyId = Entity Identifier, no invented trustFramework.
            assertEquals(
                buildJsonObject {
                    put("type", "OpenIDFederation")
                    put("policyId", "https://issuer.example.com")
                },
                payload["termsOfUse"],
            )
            assertEquals("https://issuer.example.com", payload["issuer"]?.jsonPrimitive?.content)
        }

    @Test
    fun nonFederationIssuerAddsNoTermsOfUse() =
        runTest {
            var captured: JsonObject? = null
            val result =
                newHandler(capturedPayload = { captured = it }).issueCredential(
                    request = CredentialRequest(format = CredentialFormat.JWT_VC_JSON_LD.value),
                    context = makeContext(types = listOf("VerifiableCredential", "DigitalProductPassport")),
                )

            assertTrue(result.isOk, "issuance must succeed: ${if (result.isErr) result.error else ""}")
            assertNull(assertNotNull(captured)["termsOfUse"])
        }

    @Test
    fun federationTermsOfUseIsAppendedToCallerTermsAndCannotBeForged() =
        runTest {
            val callerTerms =
                buildJsonObject {
                    put("type", "IssuerPolicy")
                    put("id", "https://issuer.example.com/policies/1")
                }
            var captured: JsonObject? = null
            val appended =
                newHandler(capturedPayload = { captured = it }).issueCredential(
                    request = CredentialRequest(format = CredentialFormat.JWT_VC_JSON_LD.value),
                    context = makeContext(types = listOf("VerifiableCredential", "DigitalProductPassport")).copy(
                        vcdmProperties = buildJsonObject { put("termsOfUse", callerTerms) },
                        federationEntityIdentifier = "https://issuer.example.com",
                    ),
                )
            assertTrue(appended.isOk, "issuance must succeed: ${if (appended.isErr) appended.error else ""}")
            val terms = assertNotNull(captured)["termsOfUse"]?.jsonArray ?: error("termsOfUse must become an array")
            assertEquals(2, terms.size)
            assertEquals(callerTerms, terms[0])
            assertEquals("OpenIDFederation", terms[1].jsonObject["type"]?.jsonPrimitive?.content)

            val forged =
                newHandler().issueCredential(
                    request = CredentialRequest(format = CredentialFormat.JWT_VC_JSON_LD.value),
                    context = makeContext(types = listOf("VerifiableCredential", "DigitalProductPassport")).copy(
                        vcdmProperties =
                            buildJsonObject {
                                putJsonObject("termsOfUse") {
                                    put("type", "OpenIDFederation")
                                    put("policyId", "https://other.example.com")
                                }
                            },
                        federationEntityIdentifier = "https://issuer.example.com",
                    ),
                )
            assertTrue(forged.isErr, "a caller-supplied OpenIDFederation entry must be refused")
        }

    @Test
    fun issueCredentialWithFutureDataValidityPreservesItWithoutNbf() =
        runTest {
            var captured: JsonObject? = null
            val futureValidFrom = Instant.parse("2099-01-01T00:00:00Z")
            val futureValidUntil = Instant.parse("2100-01-01T00:00:00Z")
            val result =
                newHandler(capturedPayload = { captured = it }).issueCredential(
                    request = CredentialRequest(format = CredentialFormat.JWT_VC_JSON_LD.value),
                    context = makeContext(types = listOf("VerifiableCredential", "DigitalProductPassport")).copy(
                        validFrom = futureValidFrom,
                        validUntil = futureValidUntil,
                    ),
                )

            assertTrue(result.isOk, "future data validity must not be rejected at issuance")
            val payload = assertNotNull(captured)
            assertEquals(futureValidFrom.toString(), payload["validFrom"]?.jsonPrimitive?.content)
            assertEquals(futureValidUntil.toString(), payload["validUntil"]?.jsonPrimitive?.content)
            assertTrue(payload["iat"]!!.jsonPrimitive.long < futureValidFrom.epochSeconds)
            assertTrue(payload["nbf"] == null)
        }

    @Test
    fun issueCredentialWithFutureValidityDurationDerivesEndFromDataStart() =
        runTest {
            var captured: JsonObject? = null
            val futureValidFrom = Instant.parse("2099-01-01T00:00:00Z")
            val result =
                newHandler(capturedPayload = { captured = it }).issueCredential(
                    request = CredentialRequest(format = CredentialFormat.JWT_VC_JSON_LD.value),
                    context = makeContext(types = listOf("VerifiableCredential", "DigitalProductPassport")).copy(
                        validFrom = futureValidFrom,
                        expirationInDays = 1,
                    ),
                )

            assertTrue(result.isOk)
            val payload = assertNotNull(captured)
            assertEquals("2099-01-02T00:00:00Z", payload["validUntil"]?.jsonPrimitive?.content)
            assertEquals(futureValidFrom.epochSeconds + 24L * 60L * 60L, payload["exp"]?.jsonPrimitive?.long)
            assertTrue(payload["iat"]!!.jsonPrimitive.long < futureValidFrom.epochSeconds)
            assertTrue(payload["nbf"] == null)
        }

    @Test
    fun clockSkewChangesIatWithoutShorteningConfiguredSignatureLifetime() =
        runTest {
            var captured: JsonObject? = null
            val context =
                makeContext(types = listOf("VerifiableCredential", "DigitalProductPassport")).copy(
                    issuanceClockSkewInSeconds = 90,
                    expirationInDays = 1,
                )

            val result =
                newHandler(capturedPayload = { captured = it }).issueCredential(
                    CredentialRequest(format = CredentialFormat.JWT_VC_JSON_LD.value),
                    context,
                )

            assertTrue(result.isOk, "issuance must succeed: ${if (result.isErr) result.error else ""}")
            val payload = assertNotNull(captured)
            val validFrom = Instant.parse(payload["validFrom"]!!.jsonPrimitive.content).epochSeconds
            val validUntil = Instant.parse(payload["validUntil"]!!.jsonPrimitive.content).epochSeconds
            val iat = payload["iat"]!!.jsonPrimitive.content.toLong()
            val exp = payload["exp"]!!.jsonPrimitive.content.toLong()
            assertEquals(90L, validFrom - iat, "clock skew belongs only to iat")
            assertEquals(
                validUntil,
                exp,
                "issuer policy gives signature expiry and credential validity the same wall-clock end",
            )
        }

    @Test
    fun issueCredentialPreservesVcdm2PropertiesAndUnknownExtensions() =
        runTest {
            var captured: JsonObject? = null
            val result =
                newHandler(capturedPayload = { captured = it }).issueCredential(
                    CredentialRequest(format = CredentialFormat.JWT_VC_JSON_LD.value),
                    makeContext(types = listOf("VerifiableCredential", "DigitalProductPassport")).copy(
                        vcdmProperties = buildJsonObject {
                            putJsonObject("credentialSchema") {
                                put("id", "https://issuer.example/schema")
                                put("type", "JsonSchema")
                            }
                            putJsonArray("evidence") {
                                add(buildJsonObject {
                                    put("type", "DocumentVerification")
                                    put("id", "https://issuer.example/evidence/1")
                                })
                            }
                            put("name", buildJsonObject {
                                put("@value", "Passeport")
                                put("@language", "fr")
                            })
                            put("description", "A credential")
                            put("refreshService", buildJsonObject {
                                put("id", "https://issuer.example/refresh")
                                put("type", "ManualRefreshService")
                            })
                            put("termsOfUse", buildJsonObject {
                                put("type", "IssuerPolicy")
                                put("id", "https://issuer.example/terms")
                            })
                            put("relatedResource", buildJsonObject {
                                put("id", "https://issuer.example/resource")
                                put("mediaType", "application/json")
                                putJsonArray("digestSRI") { add(JsonPrimitive("sha256-abc")) }
                            })
                            put("https://issuer.example/ext", buildJsonObject {
                                put("nested", "retained")
                            })
                        },
                    ),
                )

            assertTrue(result.isOk, "issuance must succeed: ${if (result.isErr) result.error else ""}")
            val payload = assertNotNull(captured)
            assertNotNull(payload["credentialSchema"])
            assertNotNull(payload["evidence"])
            assertNotNull(payload["name"])
            assertNotNull(payload["description"])
            assertNotNull(payload["refreshService"])
            assertNotNull(payload["termsOfUse"])
            assertNotNull(payload["relatedResource"])
            assertEquals("retained", payload["https://issuer.example/ext"]?.jsonObject?.get("nested")?.jsonPrimitive?.content)
        }

    @Test
    fun issueCredentialRejectsCallerAttemptsToOverrideServerControlledVcdmProperties() =
        runTest {
            val handler = newHandler(kms = TestKmsMock())
            val result =
                handler.issueCredential(
                    CredentialRequest(format = CredentialFormat.JWT_VC_JSON_LD.value),
                    makeContext(types = listOf("VerifiableCredential", "DigitalProductPassport")).copy(
                        vcdmProperties = buildJsonObject {
                            put("issuer", "https://attacker.example")
                        },
                    ),
                )

            assertTrue(result.isErr)
            assertEquals("invalid_vcdm_credential", result.error.code)
        }

    @Test
    fun issueCredentialReservesEmbedsAndBindsVcdm2StatusBeforeReturning() =
        runTest {
            var captured: JsonObject? = null
            val enricher = RecordingVcdm2StatusEnricher()
            val result =
                newHandler(capturedPayload = { captured = it }, statusEnricher = enricher).issueCredential(
                    CredentialRequest(format = CredentialFormat.JWT_VC_JSON_LD.value),
                    makeContext(types = listOf("VerifiableCredential", "DigitalProductPassport"), attributes = emptyMap()).copy(
                        subject = "urn:proof-holder:v20",
                        credentialId = "https://example.com/credentials/v20",
                        statusListBinding = StatusListBinding(
                            statusListCorrelationId = "credential-status",
                            spec = StatusListSpec.BITSTRING_STATUS_LIST,
                        ),
                        credentialSubjects = listOf(
                            buildJsonObject {
                                put("id", "https://example.com/subjects/v20-one")
                                put("name", "One")
                            },
                            buildJsonObject {
                                put("id", "https://example.com/subjects/v20-two")
                                put("name", "Two")
                            },
                        ),
                    ),
                )

            assertTrue(result.isOk, "status-enabled issuance must succeed: ${if (result.isErr) result.error else ""}")
            val payload = assertNotNull(captured)
            assertNotNull(payload["credentialStatus"])
            assertNotNull(payload["jti"]?.jsonPrimitive?.content)
            assertEquals("https://example.com/credentials/v20", payload["id"]?.jsonPrimitive?.content)
            assertEquals("https://example.com/credentials/v20", payload["jti"]?.jsonPrimitive?.content)
            assertEquals(payload["jti"], payload["id"])
            assertNotEquals(payload["id"]?.jsonPrimitive?.content, "https://example.com/subjects/v20-one")
            assertNotEquals(payload["id"]?.jsonPrimitive?.content, "https://example.com/subjects/v20-two")
            assertNotEquals(payload["iss"]?.jsonPrimitive?.content, "urn:proof-holder:v20")
            assertIs<JsonArray>(payload["credentialSubject"])
            assertNull(payload["sub"], "VCDM 2.0 producer must not synthesize optional sub from subject objects")
            assertEquals(enricher.handle, enricher.boundHandle)
            assertEquals(payload["jti"]?.jsonPrimitive?.content, enricher.boundCredentialId)
            assertEquals(null, enricher.boundCredentialHash)
        }

    @Test
    fun issueCredentialUsesVcdm2ProtectedContentTypes() =
        runTest {
            val jwtService = RecordingJwtService()
            val handler =
                VcLdJsonJwtFormatHandler(
                    signatureService = (jwtService).asSignatureServiceFixture(),
                    kms = TestKmsMock(),
                    issuerKeyIdResolver = StubIssuerKeyIdResolver,
                    contextValidator = JsonLdContextValidator(bundleLoader),
                    schemaValidator = JsonLdSchemaValidator(schemaRegistry),
                )

            val result =
                handler.issueCredential(
                    CredentialRequest(format = CredentialFormat.JWT_VC_JSON_LD.value),
                    makeContext(types = listOf("VerifiableCredential", "DigitalProductPassport")),
                )

            assertTrue(result.isOk)
            val protectedHeader = assertNotNull(jwtService.lastArgs?.opts?.protectedHeader)
            assertEquals("vc+jwt", protectedHeader["typ"]?.jsonPrimitive?.content)
            assertEquals("vc", protectedHeader["cty"]?.jsonPrimitive?.content)
        }

    @Test
    fun didSigningEmitsValidatedDidUrlKidAndIgnoresRequestKeyFields() =
        runTest {
            val jwtService = RecordingJwtService()
            val handler =
                VcLdJsonJwtFormatHandler(
                    signatureService = (jwtService).asSignatureServiceFixture(),
                    kms = TestKmsMock(),
                    issuerKeyIdResolver = AcceptingIssuerKeyIdResolver,
                    contextValidator = JsonLdContextValidator(bundleLoader),
                    schemaValidator = JsonLdSchemaValidator(schemaRegistry),
                )
            val context =
                makeContext(
                    types = listOf("VerifiableCredential", "DigitalProductPassport"),
                    attributes = mapOf("kid" to JsonPrimitive("attacker-kid"), "alg" to JsonPrimitive("none")),
                ).copy(
                    signingKeyMode = SigningKeyMode.Did("jwk"),
                    signingVerificationMethodId = "did:jwk:issuer#0",
                )

            val result =
                handler.issueCredential(
                    CredentialRequest(
                        format = CredentialFormat.JWT_VC_JSON_LD.value,
                        additionalParameters =
                            mapOf(
                                "kid" to JsonPrimitive("request-kid"),
                                "x5c" to JsonPrimitive("request-certificate"),
                                "alg" to JsonPrimitive("none"),
                            ),
                    ),
                    context,
                )

            assertTrue(result.isOk)
            val header = assertNotNull(jwtService.lastArgs?.opts?.protectedHeader)
            assertEquals("vc+jwt", header["typ"]?.jsonPrimitive?.content)
            assertEquals("vc", header["cty"]?.jsonPrimitive?.content)
            assertEquals("did:jwk:issuer#0", header["kid"]?.jsonPrimitive?.content)
            assertEquals(setOf("typ", "cty", "kid"), header.keys)
            // OID4VCI 1.0 §14.4: a DID-signed credential names its DID, not the Credential Issuer URL.
            val payload = assertNotNull(jwtService.lastArgs?.payload as? JsonObject)
            assertEquals("did:jwk:issuer", payload["iss"]?.jsonPrimitive?.content)
            assertEquals("did:jwk:issuer", payload["issuer"]?.jsonPrimitive?.content)
        }

    @Test
    fun jwkSigningEmitsServerResolvedThumbprintAndIgnoresPayloadIdentifierFields() =
        runTest {
            val key = Jwk(kty = JwaKeyType.EC, crv = JwaCurve.P_256, x = "test-x", y = "test-y")
            val kms = TestKmsMock().also { it.putTestJwk("issuer-signing-untp", key) }
            val jwtService = RecordingJwtService()
            val handler =
                VcLdJsonJwtFormatHandler(
                    signatureService = (jwtService).asSignatureServiceFixture(),
                    kms = kms,
                    issuerKeyIdResolver = StubIssuerKeyIdResolver,
                    contextValidator = JsonLdContextValidator(bundleLoader),
                    schemaValidator = JsonLdSchemaValidator(schemaRegistry),
                )
            val result =
                handler.issueCredential(
                    CredentialRequest(
                        format = CredentialFormat.JWT_VC_JSON_LD.value,
                        additionalParameters = mapOf("kid" to JsonPrimitive("request-kid"), "alg" to JsonPrimitive("none")),
                    ),
                    makeContext(
                        types = listOf("VerifiableCredential", "DigitalProductPassport"),
                        attributes = mapOf("kid" to JsonPrimitive("payload-kid"), "alg" to JsonPrimitive("none")),
                    ).copy(signingKeyMode = SigningKeyMode.JwkThumbprint),
                )

            assertTrue(result.isOk)
            val expected = generateJwkThumbprintUri(key.toPublicKey())
            assertEquals(expected, jwtService.lastArgs?.opts?.protectedHeader?.get("kid")?.jsonPrimitive?.content)
            assertEquals(setOf("typ", "cty", "kid"), jwtService.lastArgs?.opts?.protectedHeader?.keys)
        }

    @Test
    fun x5cSigningEmitsValidatedKmsChain() =
        runTest {
            val certificate = certificateChainFromPem(x5cFallbackCertificatePem).single()
            val x5c = certificate.derToBase64()
            val key = assertIs<Jwk>(certificate.getPublicKeyJwk(x5c = arrayOf(x5c)))
            val kms = TestKmsMock().also { it.putTestJwk("issuer-signing-untp", key) }
            val jwtService = RecordingJwtService()
            val handler =
                VcLdJsonJwtFormatHandler(
                    signatureService = (jwtService).asSignatureServiceFixture(),
                    kms = kms,
                    issuerKeyIdResolver = StubIssuerKeyIdResolver,
                    contextValidator = JsonLdContextValidator(bundleLoader),
                    schemaValidator = JsonLdSchemaValidator(schemaRegistry),
                )
            val result =
                handler.issueCredential(
                    CredentialRequest(format = CredentialFormat.JWT_VC_JSON_LD.value),
                    makeContext(types = listOf("VerifiableCredential", "DigitalProductPassport")).copy(signingKeyMode = SigningKeyMode.X5c),
                )

            assertTrue(result.isOk)
            assertEquals(
                listOf(x5c),
                jwtService.lastArgs?.opts?.protectedHeader?.get("x5c")?.jsonArray?.map { it.jsonPrimitive.content },
            )
            assertEquals(setOf("typ", "cty", "x5c"), jwtService.lastArgs?.opts?.protectedHeader?.keys)
        }

    @Test
    fun x5cSigningUsesConfiguredResolvedChainWhenKmsKeyHasNoChain() =
        runTest {
            val certificate = certificateChainFromPem(x5cFallbackCertificatePem).single()
            val expected = certificate.derToBase64()
            val result =
                resolveIssuerSigningHeader(
                    kms = TestKmsMock().also {
                        it.putTestJwk("issuer-signing-untp", assertIs<Jwk>(certificate.getPublicKeyJwk()))
                    },
                    issuerKeyIdResolver = StubIssuerKeyIdResolver,
                    keyAlias = "issuer-signing-untp",
                    mode = SigningKeyMode.X5c,
                    signingVerificationMethodId = null,
                    configuredX5c = arrayOf(expected),
                )

            assertTrue(result.isOk)
            assertEquals(
                listOf(expected),
                result.getOrThrow()?.get("x5c")?.jsonArray?.map { it.jsonPrimitive.content },
            )
        }

    @Test
    fun x5cSigningPrefersKmsChainOverConfiguredResolvedChain() =
        runTest {
            val certificate = certificateChainFromPem(x5cFallbackCertificatePem).single()
            val kmsX5c = certificate.derToBase64()
            val key = assertIs<Jwk>(certificate.getPublicKeyJwk(x5c = arrayOf(kmsX5c)))
            val configured = certificateChainFromPem(x5cFallbackCertificatePem).single().derToBase64()
            val result =
                resolveIssuerSigningHeader(
                    kms = TestKmsMock().also { it.putTestJwk("issuer-signing-untp", key) },
                    issuerKeyIdResolver = StubIssuerKeyIdResolver,
                    keyAlias = "issuer-signing-untp",
                    mode = SigningKeyMode.X5c,
                    signingVerificationMethodId = null,
                    configuredX5c = arrayOf(configured),
                )

            assertTrue(result.isOk)
            assertEquals(
                listOf(kmsX5c),
                result.getOrThrow()?.get("x5c")?.jsonArray?.map { it.jsonPrimitive.content },
            )
        }

    @Test
    fun unavailableConfiguredJwkAndX5cMaterialFailBeforeSigning() =
        runTest {
            for (mode in listOf(SigningKeyMode.JwkThumbprint, SigningKeyMode.X5c)) {
                val signer = RecordingJwtService()
                val handler =
                    VcLdJsonJwtFormatHandler(
                        signatureService = (signer).asSignatureServiceFixture(),
                        kms = TestKmsMock(),
                        issuerKeyIdResolver = StubIssuerKeyIdResolver,
                        contextValidator = JsonLdContextValidator(bundleLoader),
                        schemaValidator = JsonLdSchemaValidator(schemaRegistry),
                    )
                val result =
                    handler.issueCredential(
                        CredentialRequest(format = CredentialFormat.JWT_VC_JSON_LD.value),
                        makeContext(types = listOf("VerifiableCredential", "DigitalProductPassport")).copy(signingKeyMode = mode),
                    )
                assertTrue(result.isErr)
                assertEquals("signing_key_material_unavailable", result.error.code)
                assertEquals(null, signer.lastArgs)
            }
        }

    @Test
    fun missingOrMalformedConfiguredDidVerificationMethodFailsBeforeSigning() =
        runTest {
            for (verificationMethodId in listOf(null, "not-a-did-url")) {
                val signer = RecordingJwtService()
                val result =
                    VcLdJsonJwtFormatHandler(
                        signatureService = (signer).asSignatureServiceFixture(),
                        kms = TestKmsMock(),
                        issuerKeyIdResolver = AcceptingIssuerKeyIdResolver,
                        contextValidator = JsonLdContextValidator(bundleLoader),
                        schemaValidator = JsonLdSchemaValidator(schemaRegistry),
                    ).issueCredential(
                        CredentialRequest(format = CredentialFormat.JWT_VC_JSON_LD.value),
                        makeContext(types = listOf("VerifiableCredential", "DigitalProductPassport")).copy(
                            signingKeyMode = SigningKeyMode.Did("jwk"),
                            signingVerificationMethodId = verificationMethodId,
                        ),
                    )
                assertTrue(result.isErr)
                assertEquals("invalid_signing_verification_method", result.error.code)
                assertEquals(null, signer.lastArgs)
            }
        }

    @Test
    fun issuanceFailsWhenContextValidatorRejectsVocab() =
        runTest {
            // Inject a loader that returns a context body containing @vocab.
            val poisonedLoader =
                LinkedDataDocumentLoader { iri ->
                    when (iri) {
                        "https://www.w3.org/ns/credentials/v2" -> {
                            Ok(
                                LinkedDataDocument(
                                    documentUrl = iri,
                                    content =
                                        buildJsonObject {
                                            put(
                                                "@context",
                                                buildJsonObject { put("@vocab", JsonPrimitive("https://example.com/")) },
                                            )
                                        },
                                    contentType = "application/ld+json",
                                ),
                            )
                        }

                        else -> {
                            Err(
                                com.sphereon.jsonld.JsonLdError.LoadingDocumentFailed(
                                    iri = iri,
                                    reason = "fixture absent",
                                ),
                            )
                        }
                    }
                }
            val handler =
                VcLdJsonJwtFormatHandler(
                    signatureService = (FakeJwtService()).asSignatureServiceFixture(),
                    kms = TestKmsMock(),
                    issuerKeyIdResolver = StubIssuerKeyIdResolver,
                    contextValidator = JsonLdContextValidator(poisonedLoader),
                    schemaValidator = JsonLdSchemaValidator(schemaRegistry),
                )
            val context = makeContext(types = listOf("VerifiableCredential", "DigitalProductPassport"), extraContexts = null)
            val result =
                handler.issueCredential(
                    CredentialRequest(format = CredentialFormat.JWT_VC_JSON_LD.value),
                    context,
                )
            assertTrue(result.isErr, "@vocab must abort issuance")
            assertEquals("JSONLD_INVALID_VOCAB_MAPPING", result.error.code)
        }

    @Test
    fun issuanceProceedsWhenSchemaIsNotBundled() =
        runTest {
            // Use the empty default-style registry; schema validator returns the
            // structured "no schema is registered" violation, which Track A treats
            // as a soft pass.
            val handler =
                VcLdJsonJwtFormatHandler(
                    signatureService = (FakeJwtService()).asSignatureServiceFixture(),
                    kms = TestKmsMock(),
                    issuerKeyIdResolver = StubIssuerKeyIdResolver,
                    contextValidator = JsonLdContextValidator(bundleLoader),
                    schemaValidator = JsonLdSchemaValidator(MapBackedJsonLdSchemaRegistry(emptyMap())),
                )
            val context = makeContext(types = listOf("VerifiableCredential", "UnknownType"))
            val result =
                handler.issueCredential(
                    CredentialRequest(format = CredentialFormat.JWT_VC_JSON_LD.value),
                    context,
                )
            assertTrue(result.isOk, "missing-schema must not block issuance under Track A policy")
        }

    @Test
    fun reversedGeneratedValidityFailsBeforeSigning() =
        runTest {
            val signer = RecordingJwtService()
            val handler =
                VcLdJsonJwtFormatHandler(
                    signatureService = (signer).asSignatureServiceFixture(),
                    kms = TestKmsMock(),
                    issuerKeyIdResolver = StubIssuerKeyIdResolver,
                    contextValidator = JsonLdContextValidator(bundleLoader),
                    schemaValidator = JsonLdSchemaValidator(schemaRegistry),
                )

            val result =
                handler.issueCredential(
                    CredentialRequest(format = CredentialFormat.JWT_VC_JSON_LD.value),
                    makeContext(types = listOf("VerifiableCredential", "DigitalProductPassport")).copy(expirationInDays = -1),
                )

            assertTrue(result.isErr, "validUntil before validFrom must abort issuance")
            assertVcdmInvalidProperty(result.error, "validUntil")
            assertEquals(null, signer.lastArgs, "invalid credentials must never reach JwtService")
        }

    @Test
    fun invalidIssuerIdentifierFailsBeforeSigningThroughHandler() =
        runTest {
            val signer = RecordingJwtService()
            val handler =
                VcLdJsonJwtFormatHandler(
                    signatureService = (signer).asSignatureServiceFixture(),
                    kms = TestKmsMock(),
                    issuerKeyIdResolver = StubIssuerKeyIdResolver,
                    contextValidator = JsonLdContextValidator(bundleLoader),
                    schemaValidator = JsonLdSchemaValidator(schemaRegistry),
                )
            val result =
                handler.issueCredential(
                    CredentialRequest(format = CredentialFormat.JWT_VC_JSON_LD.value),
                    makeContext(types = listOf("VerifiableCredential", "DigitalProductPassport")).copy(issuerIdentifier = "issuer without a URI"),
                )
            assertTrue(result.isErr)
            assertVcdmInvalidProperty(result.error, "issuer")
            assertEquals(null, signer.lastArgs)
        }

    @Test
    fun proofSubjectDoesNotBecomeCredentialSubjectIdentifier() =
        runTest {
            val signer = RecordingJwtService()
            val handler =
                VcLdJsonJwtFormatHandler(
                    signatureService = (signer).asSignatureServiceFixture(),
                    kms = TestKmsMock(),
                    issuerKeyIdResolver = StubIssuerKeyIdResolver,
                    contextValidator = JsonLdContextValidator(bundleLoader),
                    schemaValidator = JsonLdSchemaValidator(schemaRegistry),
                )
            val result =
                handler.issueCredential(
                    CredentialRequest(format = CredentialFormat.JWT_VC_JSON_LD.value),
                    makeContext(types = listOf("VerifiableCredential", "DigitalProductPassport")).copy(subject = "proof-subject-not-a-credential-id"),
                )

            assertTrue(result.isOk)
            val payload = assertNotNull(signer.lastArgs?.payload as? JsonObject)
            assertNull(payload["sub"])
            assertFalse(payload["credentialSubject"]!!.jsonObject.containsKey("id"))
        }

    @Test
    fun preservesMultipleCredentialSubjectsWithoutDerivingSub() =
        runTest {
            var captured: JsonObject? = null
            val result =
                newHandler(capturedPayload = { captured = it }).issueCredential(
                    request = CredentialRequest(format = CredentialFormat.JWT_VC_JSON_LD.value),
                    context = makeContext(types = listOf("VerifiableCredential", "DigitalProductPassport"), attributes = emptyMap()).copy(
                        credentialSubjects = listOf(
                            buildJsonObject {
                                put("id", "https://example.com/subjects/one")
                                put("name", "One")
                            },
                            buildJsonObject {
                                put("id", "https://example.com/subjects/two")
                                put("name", "Two")
                            },
                        ),
                    ),
                )

            assertTrue(result.isOk)
            val payload = assertNotNull(captured)
            val subjects = assertIs<JsonArray>(payload["credentialSubject"])
            assertEquals(2, subjects.size)
            assertEquals("https://example.com/subjects/one", subjects[0].jsonObject["id"]?.jsonPrimitive?.content)
            assertEquals("https://example.com/subjects/two", subjects[1].jsonObject["id"]?.jsonPrimitive?.content)
            assertNull(payload["sub"])
        }

    @Test
    fun rejectsAmbiguousExplicitSubjectsAndAttributes() =
        runTest {
            var captured: JsonObject? = null
            val result =
                newHandler(capturedPayload = { captured = it }).issueCredential(
                    request = CredentialRequest(format = CredentialFormat.JWT_VC_JSON_LD.value),
                    context = makeContext(types = listOf("VerifiableCredential", "DigitalProductPassport")).copy(
                        credentialSubjects = listOf(buildJsonObject { put("name", "explicit") }),
                    ),
                )

            assertTrue(result.isErr)
            assertTrue(result.error.message.defaultMessage.contains("cannot both be supplied"))
            assertNull(captured)
        }

    @Test
    fun rejectsNonUriCredentialId() =
        runTest {
            var captured: JsonObject? = null
            val result =
                newHandler(capturedPayload = { captured = it }).issueCredential(
                    request = CredentialRequest(format = CredentialFormat.JWT_VC_JSON_LD.value),
                    context = makeContext(types = listOf("VerifiableCredential", "DigitalProductPassport")).copy(credentialId = "not a URI"),
                )
            assertTrue(result.isErr)
            assertEquals("invalid_vcdm_identifier", result.error.code)
            assertNull(captured)
        }

    @Test
    fun emptyCredentialSubjectAttributesAreRejectedRatherThanInferringProofSubject() =
        runTest {
            val signer = RecordingJwtService()
            val handler = VcLdJsonJwtFormatHandler(
                signatureService = (signer).asSignatureServiceFixture(),
                kms = TestKmsMock(),
                issuerKeyIdResolver = StubIssuerKeyIdResolver,
                contextValidator = JsonLdContextValidator(bundleLoader),
                schemaValidator = JsonLdSchemaValidator(schemaRegistry),
            )

            val result = handler.issueCredential(
                CredentialRequest(format = CredentialFormat.JWT_VC_JSON_LD.value),
                makeContext(types = listOf("VerifiableCredential", "DigitalProductPassport"), attributes = emptyMap()),
            )

            assertTrue(result.isErr)
            assertNull(signer.lastArgs, "an empty subject cannot be replaced with the proof subject")
        }

    @Test
    fun holderKeyRemainsDistinctFromCredentialSubjectAtSigningBoundary() =
        runTest {
            var captured: JsonObject? = null
            val handler = newHandler(capturedPayload = { captured = it })
            val result =
                handler.issueCredential(
                    CredentialRequest(format = CredentialFormat.JWT_VC_JSON_LD.value),
                    makeContext(types = listOf("VerifiableCredential", "DigitalProductPassport")).copy(
                        holderKeyId = "did:example:holder-key#key-1",
                        holderBindingKey =
                            buildJsonObject {
                                put("kty", "EC")
                                put("crv", "P-256")
                                put("x", "holder-x")
                                put("y", "holder-y")
                            },
                    ),
                )

            assertTrue(result.isOk)
            val payload = assertNotNull(captured)
            assertNull(payload["sub"], "VCDM 2.0 issuance must not derive sub from proof/holder identity")
            assertEquals(
                "did:example:holder-key#key-1",
                payload["cnf"]?.jsonObject?.get("kid")?.jsonPrimitive?.content,
            )
            assertTrue(payload["cnf"]?.jsonObject?.containsKey("jwk") != true)
        }

    @Test
    fun vcdm2ValidationRejectsMalformedValidityBeforeSigningContract() {
        val result = validateVcdm2JwtPayload(vcdm2Payload(validFrom = "not-a-date"))

        assertTrue(result.isErr)
        assertVcdmInvalidProperty(result.error, "validFrom")
    }

    @Test
    fun vcdm2ValidationAcceptsIssuerObjectAbsentOptionalClaimsAndExtensions() {
        val result =
            validateVcdm2JwtPayload(
                vcdm2Payload(
                    issuer = buildJsonObject { put("id", JsonPrimitive("https://issuer.example.com")) },
                    includeRegisteredClaims = false,
                    extension = JsonPrimitive("retained"),
                ),
            )

        assertTrue(result.isOk)
    }

    @Test
    fun vcdm2ValidationRejectsMissingIssuerAndCredentialSubject() {
        val missingIssuer = JsonObject(vcdm2Payload() - "issuer" - "iss")
        val missingSubject = JsonObject(vcdm2Payload() - "credentialSubject" - "sub")

        assertVcdmInvalidProperty(validateVcdm2JwtPayload(missingIssuer).error, "issuer")
        assertVcdmInvalidProperty(validateVcdm2JwtPayload(missingSubject).error, "credentialSubject")
    }

    @Test
    fun vcdm2ValidationRejectsEmptyCredentialSubjectArray() {
        val payload = JsonObject(vcdm2Payload(includeRegisteredClaims = false) + ("credentialSubject" to JsonArray(emptyList())))

        val result = validateVcdm2JwtPayload(payload)

        assertTrue(result.isErr)
        assertVcdmInvalidProperty(result.error, "credentialSubject")
    }

    @Test
    fun vcdm2ValidationRejectsEmptyCredentialSubjectObject() {
        val payload = JsonObject(vcdm2Payload(includeRegisteredClaims = false) + ("credentialSubject" to JsonObject(emptyMap())))

        val result = validateVcdm2JwtPayload(payload)

        assertTrue(result.isErr)
        assertVcdmInvalidProperty(result.error, "credentialSubject")
    }

    @Test
    fun vcdm2ValidationAcceptsCredentialSubjectContainingOnlyId() {
        val payload = JsonObject(
            vcdm2Payload(includeRegisteredClaims = false) +
                ("credentialSubject" to buildJsonObject { put("id", JsonPrimitive("did:example:holder123")) }),
        )

        val result = validateVcdm2JwtPayload(payload)

        assertTrue(result.isOk)
    }

    @Test
    fun vcdm2ValidationAcceptsCredentialSubjectClaimsWithoutId() {
        val payload = JsonObject(
            vcdm2Payload(includeRegisteredClaims = false) +
                ("credentialSubject" to buildJsonObject { put("family_name", JsonPrimitive("Doe")) }),
        )

        assertTrue(validateVcdm2JwtPayload(payload).isOk)
    }

    @Test
    fun vcdm2ValidationAcceptsFractionalNumericDatesAndRejectsNonFiniteValues() {
        val fractional =
            JsonObject(
                vcdm2Payload(includeRegisteredClaims = false) +
                    mapOf(
                        "iat" to JsonPrimitive(100.25),
                        "nbf" to JsonPrimitive(100.5),
                        "exp" to JsonPrimitive(200.75),
                    ),
            )
        assertTrue(validateVcdm2JwtPayload(fractional).isOk)

        val nonFinite = JsonObject(vcdm2Payload(includeRegisteredClaims = false) + ("iat" to JsonPrimitive(Double.NaN)))
        val nonFiniteError = assertIs<VcdmError.InvalidJwtClaim>(validateVcdm2JwtPayload(nonFinite).error.sourceAs())
        assertEquals("iat", nonFiniteError.claim)
    }

    @Test
    fun vcdm2ValidationDoesNotInventSubjectClaimForMultipleSubjects() {
        val payload =
            buildJsonObject {
                put("@context", JsonPrimitive(VcdmProfiles.V2_0_CONTEXT))
                putJsonArray("type") { add(JsonPrimitive("VerifiableCredential")) }
                put("issuer", JsonPrimitive("https://issuer.example.com"))
                putJsonArray("credentialSubject") {
                    add(buildJsonObject { put("id", JsonPrimitive("did:example:one")); put("family_name", JsonPrimitive("One")) })
                    add(buildJsonObject { put("id", JsonPrimitive("did:example:two")); put("family_name", JsonPrimitive("Two")) })
                }
            }

        assertTrue(validateVcdm2JwtPayload(payload).isOk)
        assertTrue(
            validateVcdm2JwtPayload(
                JsonObject(payload + ("sub" to JsonPrimitive("did:example:one"))),
            ).isErr,
        )
    }

    @Test
    fun vcdm2ValidationRejectsWrongRegisteredClaimTypesAndInconsistentSignatureTimeOrdering() {
        val wrongType = JsonObject(vcdm2Payload() + ("iat" to JsonPrimitive("1700000000")))
        val wrongOrder =
            JsonObject(
                vcdm2Payload(
                    includeRegisteredClaims = false,
                ) +
                    mapOf(
                        "iat" to JsonPrimitive(200L),
                        "nbf" to JsonPrimitive(100L),
                        "exp" to JsonPrimitive(150L),
                    ),
            )

        val wrongTypeError = assertIs<VcdmError.InvalidJwtClaim>(validateVcdm2JwtPayload(wrongType).error.sourceAs())
        assertEquals("iat", wrongTypeError.claim)
        val wrongOrderError = assertIs<VcdmError.InvalidJwtClaim>(validateVcdm2JwtPayload(wrongOrder).error.sourceAs())
        assertEquals("exp", wrongOrderError.claim)
    }

    private fun vcdm2Payload(
        validFrom: String = "2026-01-01T00:00:00Z",
        issuer: JsonElement = JsonPrimitive("https://issuer.example.com"),
        includeRegisteredClaims: Boolean = true,
        extension: JsonElement? = null,
    ): JsonObject =
        buildJsonObject {
            put("@context", JsonPrimitive(VcdmProfiles.V2_0_CONTEXT))
            putJsonArray("type") { add(JsonPrimitive("VerifiableCredential")) }
            put("issuer", issuer)
            put("validFrom", JsonPrimitive(validFrom))
            put("credentialSubject", buildJsonObject {
                put("id", JsonPrimitive("did:example:holder123"))
                put("name", JsonPrimitive("Alice"))
            })
            if (includeRegisteredClaims) {
                put("iss", JsonPrimitive("https://issuer.example.com"))
                put("sub", JsonPrimitive("did:example:holder123"))
                put("iat", JsonPrimitive(100L))
                put("exp", JsonPrimitive(200L))
            }
            extension?.let { put("https://example.com/extension", it) }
        }

    /**
     * Fake JwtService that captures the payload it was asked to sign and
     * emits a deterministic compact-JWS string.
     */
    private open class FakeJwtService(
        private val onPayload: ((JsonObject) -> Unit)? = null,
    ) : JwtService {
        override val commands: JwtService.Commands
            get() = throw UnsupportedOperationException("not used in tests")

        open override suspend fun createJwsCompact(args: CreateJwsArgs): IdkResult<JwtCompactResult, IdkError> {
            val payload =
                args.payload as? JsonObject
                    ?: error("VcLdJsonJwtFormatHandler must pass a JsonObject payload")
            onPayload?.invoke(payload)
            // Encode the payload deterministically (no signing) so tests can
            // also decode the JWT body when needed.
            val encoded = Json.encodeToString(JsonObject.serializer(), payload)
            return Ok(JwtCompactResult(jwt = "eyJhbGciOiJFUzI1NiJ9.${encoded.encodeToByteArray().encodeToBase64Url()}.fakesig"))
        }

        override suspend fun prepareJws(args: CreateJwsJsonArgs): IdkResult<PreparedJwsObject, IdkError> = throw UnsupportedOperationException("not used in tests")

        override suspend fun createJwsJsonFlattened(args: CreateJwsJsonArgs): IdkResult<JwsJsonFlattened, IdkError> = throw UnsupportedOperationException("not used in tests")

        override suspend fun createJwsJsonGeneral(args: CreateJwsJsonArgs): IdkResult<JwsJsonGeneral, IdkError> = throw UnsupportedOperationException("not used in tests")

        override suspend fun verifyJws(args: VerifyJwsArgs): IdkResult<JwsValidationResult, IdkError> = throw UnsupportedOperationException("not used in tests")

        override fun assembleJwsGeneral(
            prepared: PreparedJwsObject,
            signatureBytes: ByteArray
        ) = throw UnsupportedOperationException("not used in tests")

        override fun assembleJwsFlattened(
            prepared: PreparedJwsObject,
            signatureBytes: ByteArray
        ) = throw UnsupportedOperationException("not used in tests")

        override fun assembleJwsCompact(
            prepared: PreparedJwsObject,
            signatureBytes: ByteArray
        ) = throw UnsupportedOperationException("not used in tests")
    }

    private class RecordingJwtService : FakeJwtService() {
        var lastArgs: CreateJwsArgs? = null

        override suspend fun createJwsCompact(args: CreateJwsArgs): IdkResult<JwtCompactResult, IdkError> {
            lastArgs = args
            return super.createJwsCompact(args)
        }
    }

    private class RecordingVcdm2StatusEnricher : CredentialStatusEnricher {
        val handle = StatusReservationHandle("status-list", 9)
        var boundHandle: StatusReservationHandle? = null
        var boundCredentialId: String? = null
        var boundCredentialHash: String? = null

        override suspend fun reserve(context: StatusEnrichmentContext): IdkResult<ReservedStatus, IdkError> =
            Ok(
                ReservedStatus(
                    handle = handle,
                    claim = buildJsonObject {
                        put("id", "https://issuer.example/status#9")
                        put("type", "BitstringStatusListEntry")
                        put("statusPurpose", "revocation")
                        put("statusListIndex", "9")
                        put("statusListCredential", "https://issuer.example/status")
                    },
                    mergeTarget = StatusClaimMergeTarget.VC_CREDENTIAL_STATUS,
                ),
            )

        override suspend fun bind(
            handle: StatusReservationHandle,
            credentialId: String?,
            credentialHash: String?,
        ): IdkResult<Unit, IdkError> {
            boundHandle = handle
            boundCredentialId = credentialId
            boundCredentialHash = credentialHash
            return Ok(Unit)
        }

        override suspend fun cancel(handle: StatusReservationHandle): IdkResult<Unit, IdkError> = Ok(Unit)
    }
}

private fun assertVcdmInvalidProperty(error: IdkError, property: String) {
    val invalid = assertIs<VcdmError.InvalidProperty>(error.sourceAs())
    assertEquals(property, invalid.property)
}

private object StubIssuerKeyIdResolver : com.sphereon.openid.oid4vci.issuer.impl.signing.IssuerKeyIdResolver {
    override suspend fun resolveDidVerificationMethodId(
        keyAlias: String,
        didMethod: String,
    ): IdkResult<String, IdkError> = error("DID signing is not used by this fixture")

    override suspend fun resolvePublicJwk(keyAlias: String): IdkResult<JsonObject, IdkError> =
        error("JWK signing is not used by this fixture")
}

private object AcceptingIssuerKeyIdResolver : IssuerKeyIdResolver {
    override suspend fun resolveDidVerificationMethodId(
        keyAlias: String,
        didMethod: String,
    ): IdkResult<String, IdkError> = Ok("did:$didMethod:issuer#0")

    override suspend fun validateDidVerificationMethodId(
        keyAlias: String,
        verificationMethodId: String,
    ): IdkResult<String, IdkError> = Ok(verificationMethodId)

    override suspend fun resolvePublicJwk(keyAlias: String): IdkResult<JsonObject, IdkError> =
        error("not used")
}
