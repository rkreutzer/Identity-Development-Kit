/* Copyright 2026 Sphereon International B.V. Licensed under the Apache License, Version 2.0. */
package com.sphereon.identity.matching.protection

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.error.ErrorCategory
import com.sphereon.core.api.error.IdkError

/**
 * The single place where a tenant's identifier-protection keys are created.
 *
 * Blind indexes and identifier ciphertext are only stable while the tenant keeps using the key that
 * produced them. [IdentifierProtector] therefore never creates a key: protecting, blind indexing and
 * revealing a value all refuse with [IdentifierProtectionErrors.KEY_NOT_PROVISIONED] when the tenant
 * has no key. Keys are created explicitly here, during platform setup and tenant onboarding.
 *
 * [provisionKeys] is idempotent. A key that already exists under any provider is kept as it is, so a
 * repeated call, or a call after the tenant's default KMS provider changed, never creates a second key.
 */
interface IdentifierProtectionKeyProvisioner {
    suspend fun provisionKeys(tenantId: String): IdkResult<Unit, IdkError>
}

/** Errors of identifier protection that callers handle by code. */
object IdentifierProtectionErrors {
    /** The tenant's blind-index or value-encryption key does not exist; the operation was refused. */
    const val KEY_NOT_PROVISIONED: String = "IDENTIFIER_PROTECTION_KEY_NOT_PROVISIONED"

    fun keyNotProvisioned(
        keyPurpose: String,
        tenantId: String,
    ): IdkError =
        IdkError(
            code = KEY_NOT_PROVISIONED,
            message =
                IdkError.Message(
                    i18nKey = "com.sphereon.identity.matching.error.identifier-protection-key-not-provisioned",
                    defaultMessage =
                        "The $keyPurpose identifier protection key for tenant $tenantId is not provisioned; " +
                            "identifier keys are created only by tenant onboarding or platform setup",
                ),
            category = ErrorCategory.INTERNAL,
        )

    fun isKeyNotProvisioned(error: IdkError?): Boolean = error?.code == KEY_NOT_PROVISIONED
}
