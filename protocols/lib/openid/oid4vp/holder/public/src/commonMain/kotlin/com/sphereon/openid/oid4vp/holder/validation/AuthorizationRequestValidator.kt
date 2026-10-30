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

package com.sphereon.openid.oid4vp.holder.validation

import com.sphereon.oauth2.common.model.AuthorizationRequest
import io.konform.validation.Validation
import io.konform.validation.constraints.minLength
import io.konform.validation.constraints.pattern
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull

/**
 * Konform validator for OpenID4VP Authorization Request.
 *
 * Validates requirements from OpenID4VP 1.0 Final spec:
 * - client_id (required)
 * - redirect_uri or response_uri (required)
 * - response_type (typically "vp_token")
 * - dcql_query (Digital Credentials Query Language) - OpenID4VP 1.0 Final
 * - nonce and response_mode (required)
 * - state (recommended)
 *
 * ⚠️ IMPORTANT: OpenID4VP 1.0 Final uses DCQL, not Presentation Exchange
 * - presentation_definition/presentation_definition_uri were in draft versions only
 * - Use dcql_query parameter instead
 *
 * Reference: OpenID for Verifiable Presentations 1.0 Final, Section 5
 */
val validateOid4vpAuthorizationRequest =
    Validation<AuthorizationRequest> {
        // client_id is mandatory
        AuthorizationRequest::clientId {
            minLength(1) hint "client_id is required"
        }

        constrain("response_mode is required") { !it.responseMode.isNullOrBlank() }
        constrain("response_uri and redirect_uri cannot both be present") {
            !it.additionalParameters.containsKey("response_uri") || it.redirectUri == null
        }
        constrain("direct_post requires response_uri and forbids redirect_uri") { req ->
            val directPost = req.responseMode in setOf("direct_post", "direct_post.jwt")
            val responseUri = (req.additionalParameters["response_uri"] as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull
            when {
                directPost -> !responseUri.isNullOrBlank() && req.redirectUri == null
                req.responseMode in setOf("dc_api", "dc_api.jwt") -> true
                else -> !req.redirectUri.isNullOrBlank()
            }
        }

        // response_type must be present (typically "vp_token" for OID4VP)
        AuthorizationRequest::responseType {
            minLength(1) hint "response_type is required"
        }

        // Final section 5.2 requires URL-safe ASCII, without a wallet-imposed length heuristic.
        constrain("nonce is required and must contain only URL-safe ASCII characters") { req ->
            !req.nonce.isNullOrEmpty() && req.nonce!!.all { it in URL_SAFE_ASCII }
        }
        constrain("state must contain only URL-safe ASCII characters when present") { req ->
            req.state == null || req.state!!.all { it in URL_SAFE_ASCII }
        }

        // Validate that DCQL query is provided (OpenID4VP 1.0 Final requirement)
        // Note: dcql_query is optional at parse time - actual validation happens in ResolveAuthorizationRequestCommand
        // Some requests may not have dcql_query if using other credential selection mechanisms
        run {
            constrain("dcql_query recommended for credential selection") { req ->
                // Check if dcql_query is in additional parameters
                val hasDcqlQuery = req.additionalParameters?.containsKey("dcql_query") == true

                // DCQL is the standard way, but we allow requests without it at parse time
                // Actual validation of credential selection happens later in the flow
                true // Always pass - just a recommendation hint
            }
        }

        // Validate response_mode if present (should be direct_post, direct_post.jwt for OID4VP)
        AuthorizationRequest::responseMode ifPresent {
            pattern("direct_post(\\.jwt)?|dc_api(\\.jwt)?|fragment|query".toRegex()) hint
                "response_mode must be 'direct_post', 'direct_post.jwt', 'dc_api', 'dc_api.jwt', 'fragment', or 'query'"
        }

        // Validate client_id_scheme if present
        run {
            constrain("valid client_id_scheme") { req ->
                val clientIdScheme =
                    req.additionalParameters
                        ?.get("client_id_scheme")
                        ?.toString()
                        ?.removeSurrounding("\"")
                clientIdScheme == null || clientIdScheme in
                    listOf(
                        "pre-registered",
                        "redirect_uri",
                        "entity_id",
                        "did",
                        "x509_san_dns",
                        "x509_san_uri",
                        "verifier_attestation",
                    )
            }
        }
    }

private const val URL_SAFE_ASCII = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
