/* Copyright 2026 Sphereon International B.V. Licensed under the Apache License, Version 2.0. */
package com.sphereon.oauth2.server.authorization.impl.command.token

import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.log.Log
import com.sphereon.core.api.log.LogLevel
import com.sphereon.core.api.log.LogMessage
import com.sphereon.core.api.log.SessionLogService

/** Complete bounded refusal diagnostics before the HTTP request returns. No grant values belong here. */
internal suspend fun logTokenRefusal(sessionLog: SessionLogService, message: String) {
    val sessionId = sessionLog.sessionContext.sessionId
        .takeIf { it.matches(Regex("[A-Za-z0-9_.:-]{1,160}")) } ?: "unavailable"
    Log.app().withTagAsync("OAuth2Token").execute(
        LogMessage(level = LogLevel.WARN, message = message, metadata = mapOf("session_id" to sessionId)),
    )
}

/**
 * One token-endpoint refusal line. Identifiers that do not match a plain identifier shape are
 * replaced, and the reason is the error's default message with control characters removed and
 * its length bounded. The presented secret, assertion, authorization header and request body are
 * not inputs, so they cannot reach the line.
 */
internal fun tokenRefusalLine(
    commandId: String,
    stage: String,
    clientId: String?,
    tenantId: String?,
    grantType: String?,
    error: IdkError,
): String =
    "Token request refused command=$commandId stage=$stage client_id=${clientId.refusalIdentifier()} " +
        "tenant=${tenantId.refusalIdentifier()} grant_type=${grantType.refusalIdentifier()} " +
        "code=${error.code.refusalIdentifier()} reason=${error.message.defaultMessage.refusalReason()}"

private fun String?.refusalIdentifier(): String =
    when {
        this.isNullOrBlank() -> "none"
        REFUSAL_IDENTIFIER.matches(this) -> this
        else -> "unavailable"
    }

private fun String.refusalReason(): String =
    map { if (it.isISOControl()) ' ' else it }
        .joinToString("")
        .replace(REFUSAL_WHITESPACE, " ")
        .trim()
        .take(MAX_REFUSAL_REASON_CHARS)
        .ifEmpty { "none" }

// Angle brackets keep the anonymous tenant marker readable.
private val REFUSAL_IDENTIFIER = Regex("[A-Za-z0-9_.:/@+<>-]{1,160}")
private val REFUSAL_WHITESPACE = Regex("\\s+")
private const val MAX_REFUSAL_REASON_CHARS = 160
