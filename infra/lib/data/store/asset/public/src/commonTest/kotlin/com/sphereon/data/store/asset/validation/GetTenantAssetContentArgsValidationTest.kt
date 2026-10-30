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

package com.sphereon.data.store.asset.validation

import com.sphereon.data.store.asset.command.GetTenantAssetContentArgs
import com.sphereon.data.store.asset.model.AssetNamespace
import io.konform.validation.Invalid
import io.konform.validation.Valid
import kotlin.test.Test
import kotlin.test.assertTrue

class GetTenantAssetContentArgsValidationTest {
    private val digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

    @Test
    fun shouldAcceptLowercaseHexDigestWithDigitsAndLettersInEveryNamespace() {
        for (namespace in AssetNamespace.entries) {
            val result = validateGetTenantAssetContentArgs(GetTenantAssetContentArgs(namespace, digest))
            assertTrue(result is Valid, "digest must be accepted in $namespace")
        }
    }

    @Test
    fun shouldRejectEveryHashThatIsNotACanonicalDigest() {
        val invalid =
            listOf(
                "",
                digest.dropLast(1),
                "${digest}0",
                digest.uppercase(),
                "g" + digest.drop(1),
                "$digest\n",
                " $digest",
                "$digest.png",
            )
        for (hash in invalid) {
            val result = validateGetTenantAssetContentArgs(GetTenantAssetContentArgs(AssetNamespace.BRAND, hash))
            assertTrue(result is Invalid, "hash '$hash' must be rejected")
        }
    }
}
