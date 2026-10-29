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

package com.sphereon.openid.oid4vp.verifier.impl

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.conf.OpaqueSecretResolver
import com.sphereon.core.api.encodeToHex
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.http.callback.CallbackSigning
import com.sphereon.core.api.http.callback.CallbackSigningAlgorithm
import com.sphereon.crypto.core.generic.DigestAlg
import com.sphereon.crypto.core.generic.computeHmac
import com.sphereon.di.session.SessionScope
import com.sphereon.ktor.http.client.provider.HttpClientFactory
import com.sphereon.ktor.http.client.provider.HttpClientOptions
import com.sphereon.openid.oid4vp.universal.GetAuthorizationRequestStatusOutput
import com.sphereon.openid.oid4vp.universal.universalOid4vpResponseJson
import com.sphereon.openid.oid4vp.verifier.callback.AuthorizationSessionCallbackDispatcher
import com.sphereon.openid.oid4vp.verifier.callback.AuthorizationSessionCallbackSigning
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding
import io.ktor.client.HttpClient
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.contentType
import io.ktor.http.isSuccess
import kotlinx.coroutines.CancellationException
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject

/**
 * Default callback dispatcher using the IDK HTTP abstraction ([HttpClientFactory]).
 */
@Inject
@SingleIn(SessionScope::class)
@ContributesBinding(SessionScope::class, binding = binding<AuthorizationSessionCallbackDispatcher>())
class KtorAuthorizationSessionCallbackDispatcher(
    private val httpClientFactory: HttpClientFactory,
    private val opaqueSecretResolver: OpaqueSecretResolver = OpaqueSecretResolver {
        Err(IdkError.fromString(message = "Opaque secret resolver is unavailable"))
    },
) : AuthorizationSessionCallbackDispatcher {
    override suspend fun dispatch(
        url: String,
        status: GetAuthorizationRequestStatusOutput,
    ): IdkResult<Unit, IdkError> = dispatch(url, status, null)

    override suspend fun dispatch(
        url: String,
        status: GetAuthorizationRequestStatusOutput,
        signing: AuthorizationSessionCallbackSigning?,
    ): IdkResult<Unit, IdkError> {
        var client: HttpClient? = null
        return try {
            // The status API writes its body with the same configuration; the exact bytes are signed and then sent.
            val body = universalOid4vpResponseJson.encodeToString(JsonElement.serializer(), status.toCallbackJson()).encodeToByteArray()
            val signature = when {
                signing == null -> null
                else -> {
                    val secretRef = signing.secretRef?.takeIf { it.isNotBlank() }
                        ?: return Err(IdkError.fromString(message = "Callback signing secret is missing"))
                    if ((signing.algorithm ?: CallbackSigningAlgorithm.HMAC_SHA256) != CallbackSigningAlgorithm.HMAC_SHA256) {
                        return Err(IdkError.fromString(message = "Unsupported callback signing algorithm"))
                    }
                    val secret = opaqueSecretResolver.resolve(secretRef).getOrElse {
                        return Err(IdkError.fromString(message = "Callback signing secret could not be resolved"))
                    }
                    if (secret.isBlank()) {
                        return Err(IdkError.fromString(message = "Callback signing secret is empty"))
                    }
                    CallbackSigning.HMAC_SHA256_PREFIX +
                        computeHmac(secret.encodeToByteArray(), body, DigestAlg.SHA256).encodeToHex()
                    }
            }

            val ownedClient = httpClientFactory.createClient(
                HttpClientOptions.createDefault().copy(
                    enableContentNegotiation = true,
                    followRedirects = false,
                    // Avoid leaking session/status payloads in logs by default.
                    enableLogging = false,
                ),
            )
            client = ownedClient
            val response = ownedClient.post(url) {
                contentType(ContentType.Application.Json)
                signature?.let { header(CallbackSigning.SIGNATURE_HEADER, it) }
                setBody(body)
            }
            if (response.status.isSuccess()) {
                Ok(Unit)
            } else {
                Err(IdkError.fromString(message = "Authorization session callback was not acknowledged"))
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            Err(IdkError.fromString(message = "Failed to dispatch authorization session callback"))
        } finally {
            client?.close()
        }
    }

    /**
     * The status response as the callback body. Verified data only appears when the mapper selected
     * some, so `verified_data` and its unselected members are left off the wire instead of being sent
     * as null.
     */
    private fun GetAuthorizationRequestStatusOutput.toCallbackJson(): JsonObject {
        val encoded = universalOid4vpResponseJson.encodeToJsonElement(GetAuthorizationRequestStatusOutput.serializer(), this).jsonObject
        val verifiedDataJson = encoded[VERIFIED_DATA] as? JsonObject ?: return JsonObject(encoded - VERIFIED_DATA)
        return JsonObject(encoded + (VERIFIED_DATA to JsonObject(verifiedDataJson.filterValues { it !is JsonNull })))
    }

    private companion object {
        const val VERIFIED_DATA = "verified_data"
    }
}
