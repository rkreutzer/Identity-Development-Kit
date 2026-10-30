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
 *
 */

package com.sphereon.cbor

import com.sphereon.core.compat.DateTimeUtils
import com.sphereon.core.compat.DateTimeUtilsDefault
import com.sphereon.core.compat.JsExportCompat
import com.sphereon.core.compat.LocalDateTimeKMP
import com.sphereon.core.compat.toKotlin
import com.sphereon.core.compat.toKMP
import kotlinx.datetime.LocalDate
import kotlinx.datetime.LocalDateTime
import kotlinx.datetime.TimeZone
import kotlinx.datetime.atTime
import kotlinx.datetime.toInstant
import kotlinx.datetime.toLocalDateTime
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import kotlin.jvm.JvmInline
import kotlin.time.Instant

/**
 * We are using the LocalDateTimeKmp class to deserialize and serialize again, to make really sure the date is valid and that it become a full date-time according to 18013-5
 */
@JsExportCompat
class CborTDate(
    value: cddl_tdate,
) : CborTagged<cddl_tdate>(CDDL.tdate.info!!, CborString(value.toMdocTdateString())) {
    override fun toJsonSimple(): JsonElement = JsonPrimitive(toValue())
}

@JsExportCompat
class CborFullDate(
    value: cddl_full_date,
) : CborTagged<cddl_full_date>(CDDL.full_date.info!!, CborString(value)) {
    override fun toJsonSimple(): JsonElement = JsonPrimitive(toValue())
}

@JvmInline
@Serializable
value class TDate(
    private val value: String,
) {
    init {
        // for validation purposes only
        value.toCompatDateTimeKMP()
    }

    override fun toString(): String = value.toMdocTdateString()

    fun toCborItem(): CborTDate = CborTDate(toString())

    fun encodeCbor(): ByteArray = toCborItem().encodeCbor()
}

@JsExportCompat
fun CborTDate.cborTDateToEpochSeconds(
    utils: DateTimeUtils = DateTimeUtils.DEFAULTS,
    timeZoneId: String? = null,
) = this.cborTDateToLocalDateTime(utils, timeZoneId).toInstant(utils.timeZone(timeZoneId)).epochSeconds

fun TDate.tDateToEpochSeconds(
    utils: DateTimeUtils = DateTimeUtils.DEFAULTS,
    timeZoneId: String? = null,
) = this.tDateToLocalDateTime(utils, timeZoneId).toInstant(utils.timeZone(timeZoneId)).epochSeconds

@JsExportCompat
fun CborFullDate.cborFullDateToEpochSeconds(
    utils: DateTimeUtils = DateTimeUtils.DEFAULTS,
    timeZoneId: String? = null,
) = this.cborFullDateToLocalDateTime(utils, timeZoneId).toInstant(utils.timeZone(timeZoneId)).epochSeconds

fun CborTDate.cborTDateToLocalDateTime(
    utils: DateTimeUtils = DateTimeUtils.DEFAULTS,
    timeZoneId: String? = null,
) = this.value.toLocalDateTime(utils, timeZoneId)

fun CborFullDate.cborFullDateToLocalDateTime(
    utils: DateTimeUtils = DateTimeUtils.DEFAULTS,
    timeZoneId: String? = null,
) = this.value.toLocalDateTime(utils, timeZoneId)

private fun String.toKotlinDateTime(
    utils: DateTimeUtils,
    timeZoneId: String?,
): LocalDateTime {
    val instant = runCatching { Instant.parse(this) }.getOrNull()
    return instant?.toLocalDateTime(utils.timeZone(timeZoneId))
        ?: this.toCompatDateTimeKMP().toKotlin()
}

private fun String.toCompatDateTimeKMP(): LocalDateTimeKMP {
    val instant = runCatching { Instant.parse(this) }.getOrNull()
    return instant?.toLocalDateTime(DateTimeUtils.DEFAULTS.timeZone(null))?.toKMP() ?: LocalDateTimeKMP.fromString(this)
}

private fun String.toMdocTdateString(): String {
    val instant = runCatching { Instant.parse(this) }.getOrNull()
    return instant?.toString()?.substringBefore('.')?.removeSuffix("Z")?.plus("Z")
        ?: this.toCompatDateTimeKMP().toMdocTdateString()
}

fun cddl_full_date.toLocalDateTime(
    utils: DateTimeUtils = DateTimeUtils.DEFAULTS,
    timeZoneId: String? = null,
) = runCatching { LocalDate.parse(this).atTime(0, 0) }.getOrNull() ?: this.toKotlinDateTime(utils, timeZoneId)

fun TDate.tDateToLocalDateTime(
    utils: DateTimeUtils = DateTimeUtils.DEFAULTS,
    timeZoneId: String? = null,
) = this.toString().toKotlinDateTime(utils, timeZoneId)

@JsExportCompat
fun cddl_full_date.toCborFullDate(
    utils: DateTimeUtils = DateTimeUtils.DEFAULTS,
    timeZoneId: String? = null,
) = CborFullDate(this.toLocalDateTime(utils, timeZoneId).date.toString())

fun Instant.instantToDateStringISO(
    utils: DateTimeUtils = DateTimeUtils.DEFAULTS,
    timeZoneId: String? = null,
) = utils.dateISO(timeZoneId, epochSeconds = this.epochSeconds.toInt())

@JsExportCompat
fun LocalDateTimeKMP.localDateToDateStringISO(
    utils: DateTimeUtils = DateTimeUtils.DEFAULTS,
    timeZoneId: String? = null,
) = utils.dateISO(timeZoneId, this.toInstant(utils, timeZoneId).epochSeconds.toInt())

fun LocalDateTime.localDateTimeToDateStringISO(
    utils: DateTimeUtils = DateTimeUtilsDefault.INSTANCE,
    timeZoneId: String? = null,
) = utils.dateISO(
    timeZoneId,
    epochSeconds = this.toInstant(TimeZone.of(timeZoneId ?: utils.timeZoneId)).epochSeconds.toInt(),
)

fun LocalDate.localDateToDateStringISO(
    utils: DateTimeUtils = DateTimeUtilsDefault.INSTANCE,
    timeZoneId: String? = null,
) = utils.dateISO(
    timeZoneId,
    epochSeconds =
        this
            .atTime(0, 0)
            .toInstant(TimeZone.of(timeZoneId ?: utils.timeZoneId))
            .epochSeconds
            .toInt(),
)

@JsExportCompat
fun LocalDateTimeKMP.localDateToCborFullDate() = this.toString().toCborFullDate()

/**
 * no local offset from UTC shall be used, as indicated by setting the time-offset defined in
 * RFC 3339 to "Z".
 */
fun LocalDateTimeKMP.localDateTimeToCborDate() = CborTDate(this.toMdocTdateString())
