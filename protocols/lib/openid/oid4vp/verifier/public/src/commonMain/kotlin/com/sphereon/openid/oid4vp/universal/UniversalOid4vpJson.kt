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

package com.sphereon.openid.oid4vp.universal

import com.sphereon.core.compat.JsExportIgnoreCompat
import kotlinx.serialization.json.Json

/**
 * The single serializer configuration the Universal OID4VP HTTP surface writes its response bodies
 * with.
 *
 * It lives here, in the module that owns the response models, so that the REST endpoint and the
 * tests that assert on the emitted JSON cannot drift apart: a test that hand-copies the endpoint's
 * settings proves the shape of a document the endpoint never produces. `encodeDefaults = true`
 * together with the default `explicitNulls = true` means an absent optional is emitted as an
 * explicit `null` rather than dropped, which is what a client of this API actually receives.
 */
@JsExportIgnoreCompat
val universalOid4vpResponseJson: Json =
    Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
    }
