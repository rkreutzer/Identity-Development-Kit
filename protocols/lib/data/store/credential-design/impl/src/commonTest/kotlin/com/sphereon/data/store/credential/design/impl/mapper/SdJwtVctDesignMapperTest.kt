/*
 * Copyright 2023-2026 Sphereon International B.V.
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

package com.sphereon.data.store.credential.design.impl.mapper

import com.sphereon.data.store.credential.design.model.AppliedDesignLayer
import com.sphereon.data.store.asset.model.AssetReference
import com.sphereon.data.store.credential.design.model.ClaimLabel
import com.sphereon.data.store.credential.design.model.ClaimPathSegment
import com.sphereon.data.store.credential.design.model.ClaimPresentation
import com.sphereon.data.store.credential.design.model.ClaimValueKind
import com.sphereon.data.store.credential.design.model.ClaimWidgetHint
import com.sphereon.data.store.credential.design.model.CredentialDesignRecord
import com.sphereon.data.store.credential.design.model.DesignBinding
import com.sphereon.data.store.credential.design.model.DesignClaimPath
import com.sphereon.data.store.credential.design.model.DesignHostingMode
import com.sphereon.data.store.credential.design.model.DesignSourceType
import com.sphereon.data.store.credential.design.model.LocalizedCredentialDisplay
import com.sphereon.data.store.credential.design.model.RenderVariantKind
import com.sphereon.data.store.credential.design.model.RenderVariantRecord
import com.sphereon.data.store.credential.design.model.ResolvedCredentialDesign
import com.sphereon.data.store.credential.design.model.SdPolicy
import com.sphereon.sdjwt.vc.ClaimDisplayMetadata
import com.sphereon.sdjwt.vc.ClaimInformation
import com.sphereon.sdjwt.vc.ClaimSdMetadata
import com.sphereon.sdjwt.vc.DisplayInformation
import com.sphereon.sdjwt.vc.SdJwtVcTypeMetadata
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Clock
import kotlin.time.Instant
import kotlin.uuid.Uuid

class SdJwtVctDesignMapperTest {
    private val mapper = SdJwtVctDesignMapper()

    // ---- toCanonical tests ----

    @Test
    fun toCanonicalMapsDisplaysFromMetadata() {
        val metadata =
            SdJwtVcTypeMetadata(
                vct = "https://example.com/identity_credential",
                display =
                    listOf(
                        DisplayInformation(locale = "en-US", name = "Identity Credential", description = "A digital identity credential"),
                        DisplayInformation(locale = "de-DE", name = "Identitaetsnachweis", description = null),
                    ),
            )
        val bindings = listOf(DesignBinding(vct = "https://example.com/identity_credential"))

        val record = mapper.toCanonical(metadata, bindings)

        assertEquals(2, record.displays.size)
        assertEquals("en-US", record.displays[0].locale)
        assertEquals("Identity Credential", record.displays[0].name)
        assertEquals("A digital identity credential", record.displays[0].description)
        assertEquals("de-DE", record.displays[1].locale)
        assertEquals("Identitaetsnachweis", record.displays[1].name)
        assertEquals(null, record.displays[1].description)
    }

    @Test
    fun toCanonicalMapsClaimsWithDisplayAndSdPolicy() {
        val metadata =
            SdJwtVcTypeMetadata(
                vct = "https://example.com/vc",
                claims =
                    listOf(
                        ClaimInformation(
                            path = listOf("given_name"),
                            display =
                                listOf(
                                    ClaimDisplayMetadata(locale = "en-US", label = "Given Name", description = "First name"),
                                ),
                            mandatory = true,
                            sd = ClaimSdMetadata.ALWAYS,
                            svgId = "given_name_field",
                        ),
                        ClaimInformation(
                            path = listOf("family_name"),
                            display =
                                listOf(
                                    ClaimDisplayMetadata(locale = "en-US", label = "Family Name"),
                                ),
                            mandatory = false,
                            sd = ClaimSdMetadata.NEVER,
                        ),
                    ),
            )
        val bindings = listOf(DesignBinding(vct = "https://example.com/vc"))

        val record = mapper.toCanonical(metadata, bindings)

        assertEquals(2, record.claims.size)

        val first = record.claims[0]
        assertEquals(listOf(ClaimPathSegment.Property("given_name")), first.path)
        assertEquals(1, first.labels.size)
        assertEquals("Given Name", first.labels[0].label)
        assertEquals("First name", first.labels[0].description)
        assertTrue(first.mandatory)
        assertEquals(SdPolicy.ALWAYS, first.sdPolicy)
        assertEquals(0, first.order)
        assertEquals("given_name_field", first.svgId)

        val second = record.claims[1]
        assertEquals(listOf(ClaimPathSegment.Property("family_name")), second.path)
        assertEquals(false, second.mandatory)
        assertEquals(SdPolicy.NEVER, second.sdPolicy)
        assertEquals(1, second.order)
    }

    @Test
    fun toCanonicalSetsHostingModeBasedOnSourceUrl() {
        val metadata = SdJwtVcTypeMetadata(vct = "https://example.com/vc")
        val bindings = listOf(DesignBinding(vct = "https://example.com/vc"))

        val withUrl = mapper.toCanonical(metadata, bindings, sourceUrl = "https://example.com/metadata.json")
        assertEquals(DesignHostingMode.CACHED_EXTERNAL, withUrl.hostingMode)

        val withoutUrl = mapper.toCanonical(metadata, bindings, sourceUrl = null)
        assertEquals(DesignHostingMode.LOCAL, withoutUrl.hostingMode)
    }

    @Test
    fun toCanonicalEmptyMetadataProducesEmptyDisplaysAndClaims() {
        val metadata =
            SdJwtVcTypeMetadata(
                vct = "https://example.com/empty",
                display = null,
                claims = null,
            )
        val bindings = emptyList<DesignBinding>()

        val record = mapper.toCanonical(metadata, bindings)

        assertTrue(record.displays.isEmpty())
        assertTrue(record.claims.isEmpty())
    }

    @Test
    fun toCanonicalPreservesBindings() {
        val metadata = SdJwtVcTypeMetadata(vct = "https://example.com/vc")
        val bindings =
            listOf(
                DesignBinding(vct = "https://example.com/vc", issuerId = "issuer-1"),
            )

        val record = mapper.toCanonical(metadata, bindings)

        assertEquals(1, record.bindings.size)
        assertEquals("https://example.com/vc", record.bindings[0].vct)
        assertEquals("issuer-1", record.bindings[0].issuerId)
    }

    // ---- fromCanonical tests ----

    @Test
    fun fromCanonicalMapsDisplaysToMetadata() {
        val now = Instant.parse("2025-01-01T00:00:00Z")
        val record =
            CredentialDesignRecord(
                id = Uuid.parse("00000000-0000-0000-0000-000000000001"),
                tenantId = "tenant-1",
                hostingMode = DesignHostingMode.LOCAL,
                bindings = listOf(DesignBinding(vct = "https://example.com/vc")),
                displays =
                    listOf(
                        LocalizedCredentialDisplay(locale = "en-US", name = "Test Cred", description = "A test credential"),
                    ),
                claims = emptyList(),
                createdAt = now,
                updatedAt = now,
            )

        val metadata = mapper.fromCanonical(record)

        assertEquals("https://example.com/vc", metadata.vct)
        assertNotNull(metadata.display)
        assertEquals(1, metadata.display!!.size)
        assertEquals("en-US", metadata.display!![0].locale)
        assertEquals("Test Cred", metadata.display!![0].name)
        assertEquals("A test credential", metadata.display!![0].description)
    }

    @Test
    fun fromCanonicalMapsClaimsToMetadata() {
        val now = Instant.parse("2025-01-01T00:00:00Z")
        val record =
            CredentialDesignRecord(
                id = Uuid.parse("00000000-0000-0000-0000-000000000002"),
                tenantId = "tenant-1",
                hostingMode = DesignHostingMode.LOCAL,
                bindings = listOf(DesignBinding(vct = "https://example.com/vc")),
                displays = emptyList(),
                claims =
                    listOf(
                        ClaimPresentation(
                            path = listOf(ClaimPathSegment.Property("email")),
                            labels = listOf(ClaimLabel(locale = "en-US", label = "Email", description = "Email address")),
                            mandatory = true,
                            sdPolicy = SdPolicy.ALWAYS,
                            order = 0,
                            svgId = "email_svg",
                        ),
                    ),
                createdAt = now,
                updatedAt = now,
            )

        val metadata = mapper.fromCanonical(record)

        assertNotNull(metadata.claims)
        assertEquals(1, metadata.claims!!.size)

        val claim = metadata.claims!![0]
        assertEquals(listOf("email"), claim.path)
        assertNotNull(claim.display)
        assertEquals(1, claim.display!!.size)
        assertEquals("Email", claim.display!![0].label)
        assertEquals("Email address", claim.display!![0].description)
        assertTrue(claim.mandatory)
        assertEquals(ClaimSdMetadata.ALWAYS, claim.sd)
        assertEquals("email_svg", claim.svgId)
    }

    @Test
    fun fromCanonicalEmptyDisplaysProducesNullDisplay() {
        val now = Instant.parse("2025-01-01T00:00:00Z")
        val record =
            CredentialDesignRecord(
                id = Uuid.parse("00000000-0000-0000-0000-000000000003"),
                tenantId = "tenant-1",
                hostingMode = DesignHostingMode.LOCAL,
                bindings = listOf(DesignBinding(vct = "https://example.com/vc")),
                displays = emptyList(),
                claims = emptyList(),
                createdAt = now,
                updatedAt = now,
            )

        val metadata = mapper.fromCanonical(record)

        assertEquals(null, metadata.display)
        assertEquals(null, metadata.claims)
    }

    @Test
    fun fromCanonicalClaimWithEmptyLabelsProducesNullDisplay() {
        val now = Instant.parse("2025-01-01T00:00:00Z")
        val record =
            CredentialDesignRecord(
                id = Uuid.parse("00000000-0000-0000-0000-000000000004"),
                tenantId = "tenant-1",
                hostingMode = DesignHostingMode.LOCAL,
                bindings = listOf(DesignBinding(vct = "https://example.com/vc")),
                displays = emptyList(),
                claims =
                    listOf(
                        ClaimPresentation(
                            path = listOf(ClaimPathSegment.Property("age")),
                            labels = emptyList(),
                            mandatory = false,
                            sdPolicy = SdPolicy.ALLOWED,
                            order = 0,
                        ),
                    ),
                createdAt = now,
                updatedAt = now,
            )

        val metadata = mapper.fromCanonical(record)

        assertNotNull(metadata.claims)
        assertEquals(null, metadata.claims!![0].display)
    }

    @Test
    fun fromCanonicalUsesFirstBindingVct() {
        val now = Instant.parse("2025-01-01T00:00:00Z")
        val record =
            CredentialDesignRecord(
                id = Uuid.parse("00000000-0000-0000-0000-000000000005"),
                tenantId = "tenant-1",
                hostingMode = DesignHostingMode.LOCAL,
                bindings =
                    listOf(
                        DesignBinding(vct = null, schemaId = "schema-1"),
                        DesignBinding(vct = "https://example.com/vc-type"),
                    ),
                displays = emptyList(),
                claims = emptyList(),
                createdAt = now,
                updatedAt = now,
            )

        val metadata = mapper.fromCanonical(record)

        assertEquals("https://example.com/vc-type", metadata.vct)
    }

    @Test
    fun fromCanonicalNoBindingVctDefaultsToEmpty() {
        val now = Instant.parse("2025-01-01T00:00:00Z")
        val record =
            CredentialDesignRecord(
                id = Uuid.parse("00000000-0000-0000-0000-000000000006"),
                tenantId = "tenant-1",
                hostingMode = DesignHostingMode.LOCAL,
                bindings = listOf(DesignBinding(schemaId = "schema-only")),
                displays = emptyList(),
                claims = emptyList(),
                createdAt = now,
                updatedAt = now,
            )

        val metadata = mapper.fromCanonical(record)

        assertEquals("", metadata.vct)
    }

    // ---- Claim path conversion tests ----

    @Test
    fun claimPathFromSdJwtNullBecomesAnyArrayElement() {
        val sdJwtPath: List<String?> = listOf("address", null, "street")
        val result = SdJwtVctDesignMapper.claimPathFromSdJwt(sdJwtPath)

        assertEquals(3, result.size)
        assertEquals(ClaimPathSegment.Property("address"), result[0])
        assertEquals(ClaimPathSegment.AnyArrayElement, result[1])
        assertEquals(ClaimPathSegment.Property("street"), result[2])
    }

    @Test
    fun claimPathFromSdJwtNumericStringBecomesIndex() {
        val sdJwtPath: List<String?> = listOf("items", "0", "name")
        val result = SdJwtVctDesignMapper.claimPathFromSdJwt(sdJwtPath)

        assertEquals(3, result.size)
        assertEquals(ClaimPathSegment.Property("items"), result[0])
        assertEquals(ClaimPathSegment.Index(0), result[1])
        assertEquals(ClaimPathSegment.Property("name"), result[2])
    }

    @Test
    fun claimPathFromSdJwtStringBecomesProperty() {
        val sdJwtPath: List<String?> = listOf("given_name")
        val result = SdJwtVctDesignMapper.claimPathFromSdJwt(sdJwtPath)

        assertEquals(1, result.size)
        assertEquals(ClaimPathSegment.Property("given_name"), result[0])
    }

    @Test
    fun claimPathToSdJwtPropertyBecomesString() {
        val designPath: DesignClaimPath = listOf(ClaimPathSegment.Property("email"))
        val result = SdJwtVctDesignMapper.claimPathToSdJwt(designPath)

        assertEquals(listOf("email"), result)
    }

    @Test
    fun claimPathToSdJwtAnyArrayElementBecomesNull() {
        val designPath: DesignClaimPath =
            listOf(
                ClaimPathSegment.Property("items"),
                ClaimPathSegment.AnyArrayElement,
                ClaimPathSegment.Property("value"),
            )
        val result = SdJwtVctDesignMapper.claimPathToSdJwt(designPath)

        assertEquals(listOf("items", null, "value"), result)
    }

    @Test
    fun claimPathToSdJwtIndexBecomesNumericString() {
        val designPath: DesignClaimPath =
            listOf(
                ClaimPathSegment.Property("data"),
                ClaimPathSegment.Index(3),
            )
        val result = SdJwtVctDesignMapper.claimPathToSdJwt(designPath)

        assertEquals(listOf("data", "3"), result)
    }

    @Test
    fun claimPathRoundTripPropertyAndNull() {
        val sdJwtPath: List<String?> = listOf("address", null, "city")
        val designPath = SdJwtVctDesignMapper.claimPathFromSdJwt(sdJwtPath)
        val roundTripped = SdJwtVctDesignMapper.claimPathToSdJwt(designPath)

        assertEquals(sdJwtPath, roundTripped)
    }

    // ---- SD policy mapping tests ----

    @Test
    fun mapSdPolicyAlways() {
        assertEquals(SdPolicy.ALWAYS, SdJwtVctDesignMapper.mapSdPolicy(ClaimSdMetadata.ALWAYS))
    }

    @Test
    fun mapSdPolicyAllowed() {
        assertEquals(SdPolicy.ALLOWED, SdJwtVctDesignMapper.mapSdPolicy(ClaimSdMetadata.ALLOWED))
    }

    @Test
    fun mapSdPolicyNever() {
        assertEquals(SdPolicy.NEVER, SdJwtVctDesignMapper.mapSdPolicy(ClaimSdMetadata.NEVER))
    }

    @Test
    fun mapSdPolicyReverseAlways() {
        assertEquals(ClaimSdMetadata.ALWAYS, SdJwtVctDesignMapper.mapSdPolicyReverse(SdPolicy.ALWAYS))
    }

    @Test
    fun mapSdPolicyReverseAllowed() {
        assertEquals(ClaimSdMetadata.ALLOWED, SdJwtVctDesignMapper.mapSdPolicyReverse(SdPolicy.ALLOWED))
    }

    @Test
    fun mapSdPolicyReverseNever() {
        assertEquals(ClaimSdMetadata.NEVER, SdJwtVctDesignMapper.mapSdPolicyReverse(SdPolicy.NEVER))
    }

    @Test
    fun sdPolicyRoundTrip() {
        for (sd in ClaimSdMetadata.entries) {
            val canonical = SdJwtVctDesignMapper.mapSdPolicy(sd)
            val back = SdJwtVctDesignMapper.mapSdPolicyReverse(canonical)
            assertEquals(sd, back)
        }
    }

    // ---- Round-trip tests (toCanonical -> fromCanonical) ----

    @Test
    fun roundTripPreservesVct() {
        val vct = "https://example.com/identity_credential"
        val metadata = SdJwtVcTypeMetadata(vct = vct)
        val bindings = listOf(DesignBinding(vct = vct))

        val record = mapper.toCanonical(metadata, bindings)
        val roundTripped = mapper.fromCanonical(record)

        assertEquals(vct, roundTripped.vct)
    }

    @Test
    fun roundTripPreservesDisplays() {
        val metadata =
            SdJwtVcTypeMetadata(
                vct = "https://example.com/vc",
                display =
                    listOf(
                        DisplayInformation(locale = "en-US", name = "Identity Credential", description = "A digital identity"),
                        DisplayInformation(locale = "de-DE", name = "Identitaetsnachweis", description = null),
                        DisplayInformation(locale = "nl-NL", name = "Identiteitsbewijs", description = "Een digitale identiteit"),
                    ),
            )
        val bindings = listOf(DesignBinding(vct = "https://example.com/vc"))

        val record = mapper.toCanonical(metadata, bindings)
        val roundTripped = mapper.fromCanonical(record)

        assertNotNull(roundTripped.display)
        assertEquals(3, roundTripped.display!!.size)

        assertEquals("en-US", roundTripped.display!![0].locale)
        assertEquals("Identity Credential", roundTripped.display!![0].name)
        assertEquals("A digital identity", roundTripped.display!![0].description)

        assertEquals("de-DE", roundTripped.display!![1].locale)
        assertEquals("Identitaetsnachweis", roundTripped.display!![1].name)
        assertEquals(null, roundTripped.display!![1].description)

        assertEquals("nl-NL", roundTripped.display!![2].locale)
        assertEquals("Identiteitsbewijs", roundTripped.display!![2].name)
        assertEquals("Een digitale identiteit", roundTripped.display!![2].description)
    }

    @Test
    fun roundTripPreservesClaimsWithAllSdPolicies() {
        val metadata =
            SdJwtVcTypeMetadata(
                vct = "https://example.com/vc",
                claims =
                    listOf(
                        ClaimInformation(
                            path = listOf("given_name"),
                            display = listOf(ClaimDisplayMetadata(locale = "en-US", label = "Given Name", description = "First name")),
                            mandatory = true,
                            sd = ClaimSdMetadata.ALWAYS,
                            svgId = "given_name_svg",
                        ),
                        ClaimInformation(
                            path = listOf("family_name"),
                            display = listOf(ClaimDisplayMetadata(locale = "en-US", label = "Family Name")),
                            mandatory = false,
                            sd = ClaimSdMetadata.ALLOWED,
                        ),
                        ClaimInformation(
                            path = listOf("iss"),
                            display = null,
                            mandatory = true,
                            sd = ClaimSdMetadata.NEVER,
                        ),
                    ),
            )
        val bindings = listOf(DesignBinding(vct = "https://example.com/vc"))

        val record = mapper.toCanonical(metadata, bindings)
        val roundTripped = mapper.fromCanonical(record)

        assertNotNull(roundTripped.claims)
        assertEquals(3, roundTripped.claims!!.size)

        val first = roundTripped.claims!![0]
        assertEquals(listOf("given_name"), first.path)
        assertEquals("Given Name", first.display!![0].label)
        assertEquals("First name", first.display!![0].description)
        assertTrue(first.mandatory)
        assertEquals(ClaimSdMetadata.ALWAYS, first.sd)
        assertEquals("given_name_svg", first.svgId)

        val second = roundTripped.claims!![1]
        assertEquals(listOf("family_name"), second.path)
        assertEquals("Family Name", second.display!![0].label)
        assertFalse(second.mandatory)
        assertEquals(ClaimSdMetadata.ALLOWED, second.sd)

        val third = roundTripped.claims!![2]
        assertEquals(listOf("iss"), third.path)
        assertEquals(null, third.display)
        assertTrue(third.mandatory)
        assertEquals(ClaimSdMetadata.NEVER, third.sd)
    }

    @Test
    fun roundTripPreservesNestedClaimPaths() {
        val metadata =
            SdJwtVcTypeMetadata(
                vct = "https://example.com/vc",
                claims =
                    listOf(
                        ClaimInformation(
                            path = listOf("address", "street_address"),
                            display = listOf(ClaimDisplayMetadata(locale = "en-US", label = "Street")),
                        ),
                        ClaimInformation(
                            path = listOf("nationalities", null),
                            display = listOf(ClaimDisplayMetadata(locale = "en-US", label = "Nationality")),
                        ),
                    ),
            )
        val bindings = listOf(DesignBinding(vct = "https://example.com/vc"))

        val record = mapper.toCanonical(metadata, bindings)
        val roundTripped = mapper.fromCanonical(record)

        assertNotNull(roundTripped.claims)
        assertEquals(2, roundTripped.claims!!.size)

        assertEquals(listOf("address", "street_address"), roundTripped.claims!![0].path)
        assertEquals(listOf("nationalities", null), roundTripped.claims!![1].path)
    }

    @Test
    fun roundTripPreservesMultiLocaleClaimLabels() {
        val metadata =
            SdJwtVcTypeMetadata(
                vct = "https://example.com/vc",
                claims =
                    listOf(
                        ClaimInformation(
                            path = listOf("given_name"),
                            display =
                                listOf(
                                    ClaimDisplayMetadata(locale = "en-US", label = "Given Name", description = "First name"),
                                    ClaimDisplayMetadata(locale = "de-DE", label = "Vorname", description = "Erster Name"),
                                    ClaimDisplayMetadata(locale = "fr-FR", label = "Prenom"),
                                ),
                        ),
                    ),
            )
        val bindings = listOf(DesignBinding(vct = "https://example.com/vc"))

        val record = mapper.toCanonical(metadata, bindings)
        val roundTripped = mapper.fromCanonical(record)

        assertNotNull(roundTripped.claims)
        val claim = roundTripped.claims!![0]
        assertNotNull(claim.display)
        assertEquals(3, claim.display!!.size)
        assertEquals("en-US", claim.display!![0].locale)
        assertEquals("Given Name", claim.display!![0].label)
        assertEquals("de-DE", claim.display!![1].locale)
        assertEquals("Vorname", claim.display!![1].label)
        assertEquals("Erster Name", claim.display!![1].description)
        assertEquals("fr-FR", claim.display!![2].locale)
        assertEquals("Prenom", claim.display!![2].label)
        assertEquals(null, claim.display!![2].description)
    }

    // ---- fromCanonical with fields not supported by SD-JWT VCT ----

    @Test
    fun fromCanonicalGracefullyOmitsEntryCodes() {
        // ClaimPresentation.entryCodes exists in canonical model but ClaimInformation
        // in SD-JWT VCT has no entryCodes field -- they should be silently dropped
        val now = Instant.parse("2025-01-01T00:00:00Z")
        val record =
            CredentialDesignRecord(
                id = Uuid.parse("00000000-0000-0000-0000-000000000010"),
                tenantId = "tenant-1",
                hostingMode = DesignHostingMode.LOCAL,
                bindings = listOf(DesignBinding(vct = "https://example.com/vc")),
                displays = emptyList(),
                claims =
                    listOf(
                        ClaimPresentation(
                            path = listOf(ClaimPathSegment.Property("country")),
                            labels = listOf(ClaimLabel(locale = "en-US", label = "Country")),
                            mandatory = false,
                            sdPolicy = SdPolicy.ALLOWED,
                            order = 0,
                            entryCodes = listOf("US", "NL", "DE", "FR"),
                        ),
                    ),
                createdAt = now,
                updatedAt = now,
            )

        val metadata = mapper.fromCanonical(record)

        // The claim should be present but entryCodes are not part of ClaimInformation
        assertNotNull(metadata.claims)
        assertEquals(1, metadata.claims!!.size)
        assertEquals(listOf("country"), metadata.claims!![0].path)
        assertEquals("Country", metadata.claims!![0].display!![0].label)
    }

    @Test
    fun fromCanonicalGracefullyOmitsEntryValuesFromLabels() {
        // ClaimLabel.entryValues exists in canonical model but ClaimDisplayMetadata
        // in SD-JWT VCT has no entryValues field
        val now = Instant.parse("2025-01-01T00:00:00Z")
        val record =
            CredentialDesignRecord(
                id = Uuid.parse("00000000-0000-0000-0000-000000000011"),
                tenantId = "tenant-1",
                hostingMode = DesignHostingMode.LOCAL,
                bindings = listOf(DesignBinding(vct = "https://example.com/vc")),
                displays = emptyList(),
                claims =
                    listOf(
                        ClaimPresentation(
                            path = listOf(ClaimPathSegment.Property("status")),
                            labels =
                                listOf(
                                    ClaimLabel(
                                        locale = "en-US",
                                        label = "Status",
                                        description = "Current status",
                                        entryValues = mapOf("A" to "Active", "I" to "Inactive"),
                                    ),
                                ),
                            mandatory = true,
                            sdPolicy = SdPolicy.NEVER,
                            order = 0,
                        ),
                    ),
                createdAt = now,
                updatedAt = now,
            )

        val metadata = mapper.fromCanonical(record)

        assertNotNull(metadata.claims)
        val claim = metadata.claims!![0]
        assertEquals("Status", claim.display!![0].label)
        assertEquals("Current status", claim.display!![0].description)
        // entryValues are not in ClaimDisplayMetadata -- the label and description still survive
    }

    @Test
    fun fromCanonicalIgnoresCanonicalOnlyFieldsGracefully() {
        // Fields like group, valueKind, widgetHint, markdownAllowed, unit exist
        // in ClaimPresentation but not in ClaimInformation
        val now = Instant.parse("2025-01-01T00:00:00Z")
        val record =
            CredentialDesignRecord(
                id = Uuid.parse("00000000-0000-0000-0000-000000000012"),
                tenantId = "tenant-1",
                hostingMode = DesignHostingMode.LOCAL,
                bindings = listOf(DesignBinding(vct = "https://example.com/vc")),
                displays = emptyList(),
                claims =
                    listOf(
                        ClaimPresentation(
                            path = listOf(ClaimPathSegment.Property("bio")),
                            labels = listOf(ClaimLabel(locale = "en-US", label = "Biography")),
                            mandatory = false,
                            sdPolicy = SdPolicy.ALLOWED,
                            order = 0,
                            group = "personal-info",
                            valueKind = ClaimValueKind.STRING,
                            widgetHint = ClaimWidgetHint.MULTILINE_TEXT,
                            markdownAllowed = true,
                            unit = "chars",
                        ),
                    ),
                createdAt = now,
                updatedAt = now,
            )

        val metadata = mapper.fromCanonical(record)

        // The claim should be present with basic fields preserved
        assertNotNull(metadata.claims)
        val claim = metadata.claims!![0]
        assertEquals(listOf("bio"), claim.path)
        assertEquals("Biography", claim.display!![0].label)
        assertEquals(ClaimSdMetadata.ALLOWED, claim.sd)
        // group, valueKind, widgetHint, markdownAllowed, unit are not in ClaimInformation
        // but the conversion should not fail
    }

    @Test
    fun fromCanonicalRenderVariantIdsAreNotInMetadata() {
        // CredentialDesignRecord.renderVariantIds exist but SdJwtVcTypeMetadata
        // does not carry render variant references (rendering is separate in SD-JWT VCT)
        val now = Instant.parse("2025-01-01T00:00:00Z")
        val record =
            CredentialDesignRecord(
                id = Uuid.parse("00000000-0000-0000-0000-000000000013"),
                tenantId = "tenant-1",
                hostingMode = DesignHostingMode.LOCAL,
                bindings = listOf(DesignBinding(vct = "https://example.com/vc")),
                displays =
                    listOf(
                        LocalizedCredentialDisplay(
                            locale = "en-US",
                            name = "Styled Credential",
                            preferredRenderVariantIds = listOf(Uuid.parse("00000000-0000-0000-0000-aaaaaaaaaaaa")),
                        ),
                    ),
                claims = emptyList(),
                renderVariantIds =
                    listOf(
                        Uuid.parse("00000000-0000-0000-0000-aaaaaaaaaaaa"),
                        Uuid.parse("00000000-0000-0000-0000-bbbbbbbbbbbb"),
                    ),
                createdAt = now,
                updatedAt = now,
            )

        val metadata = mapper.fromCanonical(record)

        // Display info comes through, rendering is null since no rendering data in the mapper
        assertNotNull(metadata.display)
        assertEquals(1, metadata.display!!.size)
        assertEquals("Styled Credential", metadata.display!![0].name)
        assertEquals(null, metadata.display!![0].rendering)
    }

    @Test
    fun fromCanonicalMultipleBindingsUsesFirstVct() {
        val now = Instant.parse("2025-01-01T00:00:00Z")
        val record =
            CredentialDesignRecord(
                id = Uuid.parse("00000000-0000-0000-0000-000000000014"),
                tenantId = "tenant-1",
                hostingMode = DesignHostingMode.LOCAL,
                bindings =
                    listOf(
                        DesignBinding(vct = "https://example.com/vc-type-1", issuerId = "issuer-1"),
                        DesignBinding(vct = "https://example.com/vc-type-2", issuerId = "issuer-2"),
                    ),
                displays = emptyList(),
                claims = emptyList(),
                createdAt = now,
                updatedAt = now,
            )

        val metadata = mapper.fromCanonical(record)

        // Should use first binding that has a non-null vct
        assertEquals("https://example.com/vc-type-1", metadata.vct)
    }

    @Test
    fun roundTripFullMetadataPreservesKeyFields() {
        // Comprehensive round-trip with all supported fields populated
        val metadata =
            SdJwtVcTypeMetadata(
                vct = "https://example.com/employee_credential",
                display =
                    listOf(
                        DisplayInformation(
                            locale = "en-US",
                            name = "Employee Credential",
                            description = "Proves employment at Example Corp",
                        ),
                        DisplayInformation(
                            locale = "ja-JP",
                            name = "Employee Credential JP",
                            description = null,
                        ),
                    ),
                claims =
                    listOf(
                        ClaimInformation(
                            path = listOf("employee_id"),
                            display =
                                listOf(
                                    ClaimDisplayMetadata(locale = "en-US", label = "Employee ID"),
                                    ClaimDisplayMetadata(locale = "ja-JP", label = "Employee ID JP"),
                                ),
                            mandatory = true,
                            sd = ClaimSdMetadata.NEVER,
                            svgId = "emp_id",
                        ),
                        ClaimInformation(
                            path = listOf("department"),
                            display =
                                listOf(
                                    ClaimDisplayMetadata(locale = "en-US", label = "Department", description = "Business unit"),
                                ),
                            mandatory = false,
                            sd = ClaimSdMetadata.ALWAYS,
                        ),
                        ClaimInformation(
                            path = listOf("address", null, "city"),
                            display = null,
                            mandatory = false,
                            sd = ClaimSdMetadata.ALLOWED,
                        ),
                    ),
            )
        val bindings = listOf(DesignBinding(vct = "https://example.com/employee_credential"))

        val record = mapper.toCanonical(metadata, bindings)
        val roundTripped = mapper.fromCanonical(record)

        assertEquals(metadata.vct, roundTripped.vct)

        // Displays
        assertNotNull(roundTripped.display)
        assertEquals(metadata.display!!.size, roundTripped.display!!.size)
        for (i in metadata.display!!.indices) {
            assertEquals(metadata.display!![i].locale, roundTripped.display!![i].locale)
            assertEquals(metadata.display!![i].name, roundTripped.display!![i].name)
            assertEquals(metadata.display!![i].description, roundTripped.display!![i].description)
        }

        // Claims
        assertNotNull(roundTripped.claims)
        assertEquals(metadata.claims!!.size, roundTripped.claims!!.size)
        for (i in metadata.claims!!.indices) {
            val original = metadata.claims!![i]
            val result = roundTripped.claims!![i]
            assertEquals(original.path, result.path)
            assertEquals(original.mandatory, result.mandatory)
            assertEquals(original.sd, result.sd)
            assertEquals(original.svgId, result.svgId)

            if (original.display == null) {
                assertEquals(null, result.display)
            } else {
                assertNotNull(result.display)
                assertEquals(original.display!!.size, result.display!!.size)
                for (j in original.display!!.indices) {
                    assertEquals(original.display!![j].locale, result.display!![j].locale)
                    assertEquals(original.display!![j].label, result.display!![j].label)
                    assertEquals(original.display!![j].description, result.display!![j].description)
                }
            }
        }
    }

    @Test
    fun fromCanonicalDisplayDescriptionNullRoundTrips() {
        val metadata =
            SdJwtVcTypeMetadata(
                vct = "https://example.com/vc",
                display =
                    listOf(
                        DisplayInformation(locale = "en-US", name = "No Description", description = null),
                    ),
            )
        val bindings = listOf(DesignBinding(vct = "https://example.com/vc"))

        val record = mapper.toCanonical(metadata, bindings)
        val roundTripped = mapper.fromCanonical(record)

        assertNotNull(roundTripped.display)
        assertEquals(null, roundTripped.display!![0].description)
    }

    @Test
    fun fromCanonicalIssuerNameOverrideNotInSdJwtVct() {
        // LocalizedCredentialDisplay.issuerNameOverride is canonical-only
        val now = Instant.parse("2025-01-01T00:00:00Z")
        val record =
            CredentialDesignRecord(
                id = Uuid.parse("00000000-0000-0000-0000-000000000015"),
                tenantId = "tenant-1",
                hostingMode = DesignHostingMode.LOCAL,
                bindings = listOf(DesignBinding(vct = "https://example.com/vc")),
                displays =
                    listOf(
                        LocalizedCredentialDisplay(
                            locale = "en-US",
                            name = "My Credential",
                            description = "desc",
                            issuerNameOverride = "Custom Issuer Name",
                        ),
                    ),
                claims = emptyList(),
                createdAt = now,
                updatedAt = now,
            )

        val metadata = mapper.fromCanonical(record)

        // issuerNameOverride is not in DisplayInformation, but name/description are preserved
        assertNotNull(metadata.display)
        assertEquals("My Credential", metadata.display!![0].name)
        assertEquals("desc", metadata.display!![0].description)
    }

    // ---- fromCanonical(ResolvedCredentialDesign) rendering tests ----

    @Test
    fun fromCanonicalResolvedPreservesMandatoryIndependentlyOfDisclosureAndOtherClaimFields() {
        val expected = listOf(
            ClaimInformation(
                path = listOf("address", null, "street"),
                display = listOf(ClaimDisplayMetadata("en", "Street", "Street address")),
                mandatory = true,
                sd = ClaimSdMetadata.NEVER,
                svgId = "required_street",
            ),
            ClaimInformation(
                path = listOf("nickname"),
                display = listOf(ClaimDisplayMetadata("nl", "Roepnaam", "Optionele naam")),
                mandatory = false,
                sd = ClaimSdMetadata.ALWAYS,
                svgId = "optional_nickname",
            ),
        )
        val design = mapper.toCanonical(
            SdJwtVcTypeMetadata(vct = "https://example.com/identity", claims = expected),
            listOf(DesignBinding(vct = "https://example.com/identity")),
        )
        val resolved = ResolvedCredentialDesign(
            design = design,
            renderVariants = emptyList(),
            appliedLayers = emptyList(),
            lockedFields = emptyMap(),
            resolvedAt = Instant.parse("2025-01-01T00:00:00Z"),
        )

        // Complete value equality covers path, display, mandatory, sd and svgId together.
        assertEquals(expected, mapper.fromCanonical(resolved).claims)
    }

    @Test
    fun fromCanonicalResolvedEmitsRenderingSimpleFromVariant() {
        val now = Instant.parse("2025-01-01T00:00:00Z")
        val design =
            CredentialDesignRecord(
                id = Uuid.parse("00000000-0000-0000-0000-000000000016"),
                tenantId = "tenant-1",
                hostingMode = DesignHostingMode.LOCAL,
                bindings = listOf(DesignBinding(vct = "https://example.com/eupid")),
                displays =
                    listOf(
                        LocalizedCredentialDisplay(locale = "en", name = "EU PID", description = "European Personal ID"),
                    ),
                claims = emptyList(),
                createdAt = now,
                updatedAt = now,
            )
        val variant =
            RenderVariantRecord(
                id = Uuid.parse("00000000-0000-0000-0000-000000000099"),
                tenantId = "tenant-1",
                kind = RenderVariantKind.SIMPLE_CARD,
                localeApplicability = listOf("en"),
                logo =
                    AssetReference(
                        uri = "https://example.com/logo.png",
                        integrity = "sha256-abc123",
                        altText = "EU PID Logo",
                    ),
                backgroundImage =
                    AssetReference(
                        uri = "https://example.com/bg.png",
                        integrity = "sha256-def456",
                    ),
                backgroundColor = "#0B5FFF",
                textColor = "#FFFFFF",
            )
        val resolved =
            ResolvedCredentialDesign(
                design = design,
                renderVariants = listOf(variant),
                appliedLayers = listOf(AppliedDesignLayer(sourceType = DesignSourceType.LOCAL_OVERRIDE, priority = 0)),
                lockedFields = emptyMap(),
                resolvedAt = now,
            )

        val metadata = mapper.fromCanonical(resolved)

        assertNotNull(metadata.display)
        val displayEn = metadata.display!!.single { it.locale == "en" }
        assertNotNull(displayEn.rendering)
        val simple = displayEn.rendering!!.simple
        assertNotNull(simple)
        assertEquals("https://example.com/logo.png", simple.logo!!.uri)
        assertEquals("sha256-abc123", simple.logo!!.uriIntegrity)
        assertEquals("EU PID Logo", simple.logo!!.altText)
        assertNull(simple.backgroundImage)
        assertEquals("#0B5FFF", simple.backgroundColor)
        assertEquals("#FFFFFF", simple.textColor)
    }

    @Test
    fun fromCanonicalResolvedFallsBackToFirstVariantWhenLocaleNotMatched() {
        val now = Instant.parse("2025-01-01T00:00:00Z")
        val design =
            CredentialDesignRecord(
                id = Uuid.parse("00000000-0000-0000-0000-000000000017"),
                tenantId = "tenant-1",
                hostingMode = DesignHostingMode.LOCAL,
                bindings = listOf(DesignBinding(vct = "https://example.com/vc")),
                displays =
                    listOf(
                        LocalizedCredentialDisplay(locale = "fr", name = "Identité", description = null),
                    ),
                claims = emptyList(),
                createdAt = now,
                updatedAt = now,
            )
        val variant =
            RenderVariantRecord(
                id = Uuid.parse("00000000-0000-0000-0000-000000000098"),
                tenantId = "tenant-1",
                kind = RenderVariantKind.SIMPLE_CARD,
                localeApplicability = listOf("en"),
                backgroundColor = "#123456",
                textColor = "#FFFFFF",
            )
        val resolved =
            ResolvedCredentialDesign(
                design = design,
                renderVariants = listOf(variant),
                appliedLayers = listOf(AppliedDesignLayer(sourceType = DesignSourceType.LOCAL_OVERRIDE, priority = 0)),
                lockedFields = emptyMap(),
                resolvedAt = now,
            )

        val metadata = mapper.fromCanonical(resolved)

        val displayFr = metadata.display!!.single { it.locale == "fr" }
        // "fr" not in localeApplicability=["en"], so falls back to first variant
        assertNotNull(displayFr.rendering)
        assertEquals("#123456", displayFr.rendering!!.simple!!.backgroundColor)
    }

    @Test
    fun fromCanonicalResolvedNoVariantsProducesNullRendering() {
        val now = Instant.parse("2025-01-01T00:00:00Z")
        val design =
            CredentialDesignRecord(
                id = Uuid.parse("00000000-0000-0000-0000-000000000018"),
                tenantId = "tenant-1",
                hostingMode = DesignHostingMode.LOCAL,
                bindings = listOf(DesignBinding(vct = "https://example.com/vc")),
                displays =
                    listOf(
                        LocalizedCredentialDisplay(locale = "en", name = "Test", description = null),
                    ),
                claims = emptyList(),
                createdAt = now,
                updatedAt = now,
            )
        val resolved =
            ResolvedCredentialDesign(
                design = design,
                renderVariants = emptyList(),
                appliedLayers = emptyList(),
                lockedFields = emptyMap(),
                resolvedAt = now,
            )

        val metadata = mapper.fromCanonical(resolved)

        val displayEn = metadata.display!!.single { it.locale == "en" }
        assertNull(displayEn.rendering)
    }
}
