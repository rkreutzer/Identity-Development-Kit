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

import com.sphereon.data.store.credential.design.mapper.CredentialDesignMapper
import com.sphereon.data.store.credential.design.model.ClaimLabel
import com.sphereon.data.store.credential.design.model.ClaimPathSegment
import com.sphereon.data.store.credential.design.model.ClaimPresentation
import com.sphereon.data.store.credential.design.model.CredentialDesignRecord
import com.sphereon.data.store.credential.design.model.DesignBinding
import com.sphereon.data.store.credential.design.model.DesignClaimPath
import com.sphereon.data.store.credential.design.model.DesignHostingMode
import com.sphereon.data.store.credential.design.model.LocalizedCredentialDisplay
import com.sphereon.data.store.credential.design.model.RenderVariantRecord
import com.sphereon.data.store.credential.design.model.ResolvedCredentialDesign
import com.sphereon.data.store.credential.design.model.SdPolicy
import com.sphereon.sdjwt.vc.ClaimDisplayMetadata
import com.sphereon.sdjwt.vc.ClaimInformation
import com.sphereon.sdjwt.vc.ClaimSdMetadata
import com.sphereon.sdjwt.vc.DisplayInformation
import com.sphereon.sdjwt.vc.LogoMetadata
import com.sphereon.sdjwt.vc.RenderingMetadata
import com.sphereon.sdjwt.vc.SdJwtVcTypeMetadata
import com.sphereon.sdjwt.vc.SimpleRenderingMethod
import kotlin.time.Clock
import kotlin.uuid.Uuid

class SdJwtVctDesignMapper : CredentialDesignMapper<SdJwtVcTypeMetadata> {
    override fun toCanonical(
        source: SdJwtVcTypeMetadata,
        bindings: List<DesignBinding>,
        sourceUrl: String?,
    ): CredentialDesignRecord {
        val now = Clock.System.now()
        val displays =
            source.display?.map { display ->
                LocalizedCredentialDisplay(
                    locale = display.locale,
                    name = display.name,
                    description = display.description,
                )
            } ?: emptyList()

        val claims =
            source.claims?.mapIndexed { index, claim ->
                val path = claimPathFromSdJwt(claim.path)
                val labels =
                    claim.display?.map { display ->
                        ClaimLabel(
                            locale = display.locale,
                            label = display.label,
                            description = display.description,
                        )
                    } ?: emptyList()
                ClaimPresentation(
                    path = path,
                    labels = labels,
                    mandatory = claim.mandatory,
                    sdPolicy = mapSdPolicy(claim.sd),
                    order = index,
                    svgId = claim.svgId,
                )
            } ?: emptyList()

        return CredentialDesignRecord(
            id = Uuid.random(),
            tenantId = "", // Set by caller
            hostingMode =
                if (sourceUrl != null) {
                    DesignHostingMode.CACHED_EXTERNAL
                } else {
                    DesignHostingMode.LOCAL
                },
            bindings = bindings,
            displays = displays,
            claims = claims,
            createdAt = now,
            updatedAt = now,
        )
    }

    override fun fromCanonical(design: CredentialDesignRecord): SdJwtVcTypeMetadata =
        fromCanonical(ResolvedCredentialDesign(design = design, renderVariants = emptyList(), appliedLayers = emptyList(), lockedFields = emptyMap(), resolvedAt = Clock.System.now()))

    fun fromCanonical(resolved: ResolvedCredentialDesign): SdJwtVcTypeMetadata {
        val design = resolved.design
        val vct = design.bindings.firstNotNullOfOrNull { it.vct } ?: ""

        val displays =
            design.displays.map { display ->
                val variant = selectRenderVariant(resolved.renderVariants, display.locale)
                DisplayInformation(
                    locale = display.locale,
                    name = display.name,
                    description = display.description,
                    rendering = buildRendering(variant),
                )
            }

        val claims =
            design.claims.map { claim ->
                val path = claimPathToSdJwt(claim.path)
                val displayList =
                    claim.labels.map { label ->
                        ClaimDisplayMetadata(
                            locale = label.locale,
                            label = label.label,
                            description = label.description,
                        )
                    }
                ClaimInformation(
                    path = path,
                    display = displayList.ifEmpty { null },
                    mandatory = claim.mandatory,
                    sd = mapSdPolicyReverse(claim.sdPolicy),
                    svgId = claim.svgId,
                )
            }

        return SdJwtVcTypeMetadata(
            vct = vct,
            display = displays.ifEmpty { null },
            claims = claims.ifEmpty { null },
        )
    }

    private fun buildRendering(variant: RenderVariantRecord?): RenderingMetadata? {
        variant ?: return null
        val simple =
            SimpleRenderingMethod(
                logo =
                    variant.logo?.let { l ->
                        LogoMetadata(uri = l.uri, uriIntegrity = l.integrity, altText = l.altText)
                    },
                backgroundColor = variant.backgroundColor,
                textColor = variant.textColor,
            )
        // Only attach rendering if at least one field is populated
        val hasContent =
            simple.logo != null || simple.backgroundColor != null || simple.textColor != null
        return if (hasContent) RenderingMetadata(simple = simple) else null
    }

    companion object {
        fun claimPathFromSdJwt(path: List<String?>): DesignClaimPath =
            path.map { segment ->
                when {
                    segment == null -> ClaimPathSegment.AnyArrayElement
                    segment.toIntOrNull() != null -> ClaimPathSegment.Index(segment.toInt())
                    else -> ClaimPathSegment.Property(segment)
                }
            }

        fun claimPathToSdJwt(path: DesignClaimPath): List<String?> =
            path.map { segment ->
                when (segment) {
                    is ClaimPathSegment.Property -> segment.name
                    is ClaimPathSegment.Index -> segment.index.toString()
                    is ClaimPathSegment.AnyArrayElement -> null
                }
            }

        fun mapSdPolicy(sd: ClaimSdMetadata): SdPolicy =
            when (sd) {
                ClaimSdMetadata.ALWAYS -> SdPolicy.ALWAYS
                ClaimSdMetadata.ALLOWED -> SdPolicy.ALLOWED
                ClaimSdMetadata.NEVER -> SdPolicy.NEVER
            }

        fun mapSdPolicyReverse(sd: SdPolicy): ClaimSdMetadata =
            when (sd) {
                SdPolicy.ALWAYS -> ClaimSdMetadata.ALWAYS
                SdPolicy.ALLOWED -> ClaimSdMetadata.ALLOWED
                SdPolicy.NEVER -> ClaimSdMetadata.NEVER
            }
    }
}
