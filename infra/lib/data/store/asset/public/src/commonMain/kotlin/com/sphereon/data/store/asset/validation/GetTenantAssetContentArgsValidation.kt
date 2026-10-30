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

import com.sphereon.data.store.asset.PublicAssetPaths
import com.sphereon.data.store.asset.command.GetTenantAssetContentArgs
import io.konform.validation.Validation

/**
 * Accepts only a [GetTenantAssetContentArgs.hash] that is a canonical asset hash, a lowercase hexadecimal digest of an
 * algorithm the blob module registers ([PublicAssetPaths.isCanonicalHash]). Whether the tenant holds an asset with that
 * hash is the asset library's answer.
 */
val validateGetTenantAssetContentArgs: Validation<GetTenantAssetContentArgs> =
    Validation {
        GetTenantAssetContentArgs::hash {
            constrain("Asset hash must be a lowercase hexadecimal content digest") { PublicAssetPaths.isCanonicalHash(it) }
        }
    }
