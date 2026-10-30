/*
 * Copyright 2026 Sphereon International B.V.
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

package com.sphereon.wallet.credential

fun walletUnitRootPrefix(): String = "wallet-units/"

fun walletUnitPath(walletUnitId: String): String = walletUnitPrefix(walletUnitId) + "/profile"

fun walletStorageProfilePath(walletUnitId: String): String = walletUnitPrefix(walletUnitId) + "/storage-profile"

fun walletCredentialRecordEnvelopePath(
    walletUnitId: String,
    credentialRecordId: String,
): String = walletCredentialPrefix(walletUnitId, credentialRecordId) + "/record"

fun walletCredentialInstanceBodyPath(
    walletUnitId: String,
    credentialRecordId: String,
    credentialInstanceId: String,
): String =
    walletCredentialPrefix(walletUnitId, credentialRecordId) +
        "/instances/" +
        walletPathSegment(credentialInstanceId, "credentialInstanceId") +
        "/body"

fun walletCredentialMetadataPath(
    walletUnitId: String,
    credentialRecordId: String,
): String = walletCredentialPrefix(walletUnitId, credentialRecordId) + "/metadata"

fun walletCredentialMetadataPrefix(walletUnitId: String): String = walletUnitPrefix(walletUnitId) + "/credentials/"

fun walletIssuancePrefix(walletUnitId: String): String = walletUnitPrefix(walletUnitId) + "/issuance/"

/** Secrets are siblings of session records, never children of a session blob's file path. */
fun walletIssuanceSecretsPrefix(walletUnitId: String): String = walletUnitPrefix(walletUnitId) + "/issuance-secrets/"

fun walletIssuanceSessionPath(
    walletUnitId: String,
    issuanceSessionId: String,
): String = walletIssuancePrefix(walletUnitId) + walletPathSegment(issuanceSessionId, "issuanceSessionId")

fun walletDeferredAccessTokenPath(
    walletUnitId: String,
    issuanceSessionId: String,
): String = walletIssuanceSecretsPrefix(walletUnitId) + walletPathSegment(issuanceSessionId, "issuanceSessionId") + "/access-token"

fun walletRefreshTokenPath(
    walletUnitId: String,
    credentialRecordId: String,
): String =
    walletIssuanceSecretsPrefix(walletUnitId) +
        walletPathSegment(credentialRecordId, "credentialRecordId") +
        "/refresh-token"

private fun walletCredentialPrefix(
    walletUnitId: String,
    credentialRecordId: String,
): String = walletCredentialMetadataPrefix(walletUnitId) + walletPathSegment(credentialRecordId, "credentialRecordId")

private fun walletUnitPrefix(walletUnitId: String): String = walletUnitRootPrefix() + walletPathSegment(walletUnitId, "walletUnitId")

fun walletPathSegment(
    value: String,
    name: String,
): String {
    val segment = value.trim()
    require(segment.isNotBlank()) { "$name must not be blank" }
    require(!segment.contains('\u0000')) { "$name must not contain null bytes" }
    require(!segment.contains('/')) { "$name must not contain '/'" }
    require(!segment.contains('\\')) { "$name must not contain '\\'" }
    require(segment != "." && segment != "..") { "$name must not be a path traversal segment" }
    return segment
}
