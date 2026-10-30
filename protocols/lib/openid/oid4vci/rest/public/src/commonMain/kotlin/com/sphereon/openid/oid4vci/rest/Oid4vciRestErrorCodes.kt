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

package com.sphereon.openid.oid4vci.rest

import com.sphereon.core.api.error.IdkError

/**
 * Codes of the errors the create credential offer and offer status commands answer for a correlation id that makes a
 * call idempotent, or for an unknown outcome. All are conflicts, so an HTTP caller is answered with 409.
 */
object Oid4vciRestErrorCodes {
    /** The correlation id was used before for a different request (or for another issuer instance, callback or template). */
    const val CORRELATION_ID_CONFLICT: String = "OID4VCI_CORRELATION_ID_CONFLICT"

    /** An earlier attempt under the correlation id has an unknown outcome until its offer has expired. */
    const val CORRELATION_ID_IN_DOUBT: String = "OID4VCI_CORRELATION_ID_IN_DOUBT"

    /** The offer created under the correlation id has expired. The id never creates a second offer, a new request needs a new id. */
    const val CORRELATION_ID_EXPIRED: String = "OID4VCI_CORRELATION_ID_EXPIRED"

    /** The offer created under the correlation id was deleted. The id is not used for another offer. */
    const val CORRELATION_ID_WITHDRAWN: String = "OID4VCI_CORRELATION_ID_WITHDRAWN"

    /** The session exists, but the protocol session that decides its outcome is gone and no terminal status was stored. */
    const val OFFER_OUTCOME_UNKNOWN: String = "OID4VCI_OFFER_OUTCOME_UNKNOWN"

    /**
     * Codes the issuer also returns after it has written. Do not use them to decide that nothing exists: read
     * [com.sphereon.openid.oid4vci.issuer.command.nothingWritten] on the error instead.
     */
    @Deprecated(
        message = "Generic error codes also follow a write. Read IdkError.nothingWritten instead.",
        replaceWith = ReplaceWith("error.nothingWritten", "com.sphereon.openid.oid4vci.issuer.command.nothingWritten"),
    )
    val REFUSED_BEFORE_ANY_WRITE: Set<String> =
        setOf(IdkError.ILLEGAL_ARGUMENT_ERROR().code, IdkError.INVALID_STATE().code, CORRELATION_ID_CONFLICT)
}
