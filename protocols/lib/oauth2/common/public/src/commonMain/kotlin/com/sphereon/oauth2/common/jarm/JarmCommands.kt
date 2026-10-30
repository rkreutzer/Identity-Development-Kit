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

package com.sphereon.oauth2.common.jarm

import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.service.ServiceCommand
import com.sphereon.core.compat.JsExportCompat
import com.sphereon.crypto.jose.jwe.JweHeader
import com.sphereon.crypto.resolution.managed.ManagedIdentifierOptsOrResult
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import kotlin.experimental.ExperimentalObjCName
import kotlin.native.ObjCName

// ============================================================================
// Create JARM Response Command
// ============================================================================

/**
 * Arguments for creating a JARM (JWT Secured Authorization Response) response.
 *
 * Per the JARM spec, the authorization response is encoded as a JWT containing
 * the standard JWT claims (iss, aud, exp) plus the authorization response parameters.
 *
 * @property responseParameters The authorization response parameters as JSON claims (e.g., code, vp_token, etc.)
 * @property state Optional state value from the original authorization request
 * @property issuer The issuer identifier (becomes JWT "iss" claim)
 * @property audience The recipient's client_id (becomes JWT "aud" claim)
 * @property signingKey Managed identifier for signing the JWT (when mode is SIGNED or SIGNED_ENCRYPTED)
 * @property encryptionRecipient Managed identifier of the recipient for encryption (when mode is ENCRYPTED or SIGNED_ENCRYPTED)
 * @property jarmConfig Configuration for JARM encoding (mode, algorithms)
 * @property expirationSeconds JWT expiration time in seconds from now (default: 300 = 5 minutes)
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("CreateJarmResponseArgs", exact = true)
@JsExportCompat
@Serializable
data class CreateJarmResponseArgs(
    val responseParameters: JsonObject,
    val state: String? = null,
    val issuer: String? = null,
    val audience: String,
    @kotlinx.serialization.Transient
    val signingKey: ManagedIdentifierOptsOrResult? = null,
    @kotlinx.serialization.Transient
    val encryptionRecipient: ManagedIdentifierOptsOrResult? = null,
    val jarmConfig: JarmConfig = JarmConfig.signed(),
    val expirationSeconds: Long = 300,
    /** Additional protected JWE headers required by a profile-specific JARM profile. */
    @kotlinx.serialization.Transient
    val protectedHeaderOverrides: JweHeader? = null,
    /** False for unsigned encrypted response-parameter envelopes; signing modes require JWT claims. */
    val appendStandardJwtClaims: Boolean = true,
)

/**
 * Result of creating a JARM response.
 *
 * @property jarmJwt The JARM-encoded authorization response (JWS, JWE, or nested JWT)
 * @property mode The JARM mode that was used
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("CreateJarmResponseResult", exact = true)
@JsExportCompat
@Serializable
data class CreateJarmResponseResult(
    val jarmJwt: String,
    val mode: JarmMode,
)

/**
 * Command for creating a JARM (JWT Secured Authorization Response) response.
 *
 * Reference: OpenID Foundation JARM spec, JWT Secured Authorization Response Mode for OAuth 2.0 (https://openid.net/specs/oauth-v2-jarm.html)
 *
 * This command creates a JWT-encoded authorization response for JARM response modes
 * (query.jwt, fragment.jwt, form_post.jwt, direct_post.jwt).
 * The response can be signed only, encrypted only, or signed-then-encrypted.
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("CreateJarmResponseCommand", exact = true)
@JsExportCompat
interface CreateJarmResponseCommand : ServiceCommand<CreateJarmResponseArgs, CreateJarmResponseResult, IdkError> {
    override val commandId: String get() = COMMAND_ID

    companion object {
        const val COMMAND_ID = "oauth2.jarm.create"
    }
}

// ============================================================================
// Verify JARM Response Command
// ============================================================================

/**
 * Arguments for verifying a JARM response.
 *
 * @property jarmJwt The JARM-encoded authorization response to verify
 * @property expectedAudience Expected audience (client_id)
 * @property expectedState Expected state value (for correlation)
 * @property decryptionKey Managed identifier for decrypting the JWE (when encrypted)
 * @property signerIdentifier Optional identifier for signature verification (if not extractable from JWT)
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("VerifyJarmResponseArgs", exact = true)
@JsExportCompat
@Serializable
data class VerifyJarmResponseArgs(
    val jarmJwt: String,
    val expectedAudience: String? = null,
    val expectedState: String? = null,
    @kotlinx.serialization.Transient
    val decryptionKey: ManagedIdentifierOptsOrResult? = null,
    @kotlinx.serialization.Transient
    val signerIdentifier: ManagedIdentifierOptsOrResult? = null,
)

/**
 * Command for verifying a JARM response.
 *
 * Reference: OpenID Foundation JARM spec, JWT Secured Authorization Response Mode for OAuth 2.0 (https://openid.net/specs/oauth-v2-jarm.html)
 *
 * This command verifies and decodes a JARM-encoded authorization response.
 * It handles:
 * - Signed-only JWTs (JWS verification)
 * - Encrypted-only JWTs (JWE decryption)
 * - Signed-then-encrypted JWTs (JWE decryption + JWS verification)
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("VerifyJarmResponseCommand", exact = true)
@JsExportCompat
interface VerifyJarmResponseCommand : ServiceCommand<VerifyJarmResponseArgs, JarmVerificationResult, IdkError> {
    override val commandId: String get() = COMMAND_ID

    companion object {
        const val COMMAND_ID = "oauth2.jarm.verify"
    }
}
