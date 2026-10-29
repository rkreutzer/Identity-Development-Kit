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

package com.sphereon.openid.oid4vci.issuer.command

import com.sphereon.core.api.error.IdkError

/**
 * Meta key with which [CreateCredentialOfferCommand] marks a refusal that happened before it wrote anything: no
 * lifecycle, issuance session, grant or offer exists afterwards. The generic error codes of such a refusal
 * (`ILLEGAL_ARGUMENT_ERROR`, `INVALID_STATE`) also follow a write, so callers that must know whether a retry may create
 * a second offer read this marker and never the code.
 */
const val OID4VCI_OFFER_NOTHING_WRITTEN_META: String = "oid4vci.offer.nothing_written"

/** This error, with the marker that the command wrote nothing before refusing. */
fun IdkError.markNothingWritten(): IdkError =
    IdkError(
        code = code,
        message = message,
        severity = severity,
        category = category,
        causes = causes,
        meta = meta + (OID4VCI_OFFER_NOTHING_WRITTEN_META to true),
        exception = exception,
        source = source,
    )

/** Whether the command that produced this error marked it as having written nothing. */
val IdkError.nothingWritten: Boolean
    get() = meta[OID4VCI_OFFER_NOTHING_WRITTEN_META] == true
