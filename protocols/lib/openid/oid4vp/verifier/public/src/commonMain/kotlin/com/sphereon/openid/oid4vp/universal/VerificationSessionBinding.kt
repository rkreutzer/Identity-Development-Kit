package com.sphereon.openid.oid4vp.universal

import com.sphereon.core.compat.JsExportCompat
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSession
import kotlinx.serialization.Serializable

/** Actual immutable verifier session pins; absent historical pins are not inferred from current settings. */
@Serializable
@JsExportCompat
data class VerificationSessionBinding(
    val instanceId: String,
    val templateId: String?,
    val templateRevision: String?,
    val queryId: String?,
    val queryVersion: Int?,
    val createdAtEpochMillis: Long,
    val expiresAtEpochMillis: Long,
)

fun AuthorizationSession.verificationBinding() = VerificationSessionBinding(
    instanceId, templateId, templateRevision, dcqlQueryId, dcqlQueryVersion, createdAt, expiresAt,
)
