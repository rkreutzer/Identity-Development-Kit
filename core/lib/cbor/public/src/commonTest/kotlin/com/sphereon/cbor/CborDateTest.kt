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
import com.sphereon.core.compat.LocalDateTimeKMP
import kotlinx.datetime.LocalDate
import kotlinx.datetime.LocalDateTime
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toInstant
import kotlinx.datetime.toLocalDateTime as instantToLocalDateTime
import kotlinx.serialization.json.JsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Instant

/**
 * Tests for CborDate.kt functions and classes
 */
class CborDateTest {
    // ========== CborTDate tests ==========

    @Test
    fun testCborTDateCreation() {
        val tdate = CborTDate("2024-01-15T10:30:00Z")
        assertNotNull(tdate)
        assertEquals(CDDL.tdate.info!!, tdate.tagNumber)
    }

    @Test
    fun testCborTDateToJsonSimple() {
        val tdate = CborTDate("2024-01-15T10:30:00Z")
        val json = tdate.toJsonSimple()
        assertIs<JsonPrimitive>(json)
        assertTrue(json.content.contains("2024-01-15"))
    }

    @Test
    fun testCborTDateToValue() {
        val tdate = CborTDate("2024-06-20T15:45:30Z")
        val value = tdate.toValue()
        assertTrue(value.contains("2024-06-20"))
    }

    // ========== CborFullDate tests ==========

    @Test
    fun testCborFullDateCreation() {
        val fullDate = CborFullDate("2024-01-15")
        assertNotNull(fullDate)
        assertEquals(CDDL.full_date.info!!, fullDate.tagNumber)
    }

    @Test
    fun testCborFullDateToJsonSimple() {
        val fullDate = CborFullDate("2024-03-20")
        val json = fullDate.toJsonSimple()
        assertIs<JsonPrimitive>(json)
        assertTrue(json.content.contains("2024-03-20"))
    }

    // ========== TDate value class tests ==========

    @Test
    fun testTDateCreation() {
        val tdate = TDate("2024-01-15T10:30:00Z")
        assertNotNull(tdate)
    }

    @Test
    fun testTDateToString() {
        val tdate = TDate("2024-01-15T10:30:00Z")
        val str = tdate.toString()
        assertTrue(str.contains("2024-01-15"))
        assertTrue(str.endsWith("Z"))
    }

    @Test
    fun testTDateToCborStructure() {
        val tdate = TDate("2024-01-15T10:30:00Z")
        val cbor = tdate.toCborItem()
        assertIs<CborTDate>(cbor)
    }

    // ========== Extension function tests ==========

    @Test
    fun testCborTDateToEpochSeconds() {
        val tdate = CborTDate("2024-01-15T00:00:00Z")
        val epochSeconds = tdate.cborTDateToEpochSeconds()
        assertTrue(epochSeconds > 0)
    }

    @Test
    fun testCborTDateToEpochSecondsWithTimezone() {
        val tdate = CborTDate("2024-01-15T12:00:00Z")
        val epochSeconds = tdate.cborTDateToEpochSeconds(timeZoneId = "UTC")
        assertTrue(epochSeconds > 0)
    }

    @Test
    fun testTDateToEpochSeconds() {
        val tdate = TDate("2024-01-15T00:00:00Z")
        val epochSeconds = tdate.tDateToEpochSeconds()
        assertTrue(epochSeconds > 0)
    }

    @Test
    fun testTDateToEpochSecondsWithTimezone() {
        val tdate = TDate("2024-01-15T12:00:00Z")
        val epochSeconds = tdate.tDateToEpochSeconds(timeZoneId = "UTC")
        assertTrue(epochSeconds > 0)
    }

    @Test
    fun tdateEpochConversionSupports2038BoundaryAnd2099() {
        val cases = listOf(
            "2038-01-19T03:14:07Z" to 2_147_483_647L,
            "2038-01-19T03:14:08Z" to 2_147_483_648L,
            "2099-12-31T23:59:59Z" to 4_102_444_799L,
        )

        cases.forEach { (dateTime, expectedEpochSeconds) ->
            val expectedUtcDateTime = Instant.parse(dateTime).instantToLocalDateTime(TimeZone.UTC)
            val tdate = TDate(dateTime)
            val cborTdate = CborTDate(dateTime)

            assertEquals(expectedEpochSeconds, tdate.tDateToEpochSeconds(timeZoneId = "UTC"))
            assertEquals(expectedEpochSeconds, cborTdate.cborTDateToEpochSeconds(timeZoneId = "UTC"))
            assertEquals(expectedUtcDateTime, tdate.tDateToLocalDateTime(timeZoneId = "UTC"))
            assertEquals(expectedUtcDateTime, cborTdate.cborTDateToLocalDateTime(timeZoneId = "UTC"))
        }
    }

    @Test
    fun tdateConversionPreservesRfc3339OffsetBeyond2038() {
        val dateTime = "2038-01-19T04:14:08+01:00"
        val expectedUtcDateTime = LocalDateTime.parse("2038-01-19T03:14:08")
        val tdate = TDate(dateTime)
        val cborTdate = CborTDate(dateTime)

        assertEquals("2038-01-19T03:14:08Z", tdate.toString())
        assertEquals("2038-01-19T03:14:08Z", cborTdate.toValue())
        assertEquals(2_147_483_648L, tdate.tDateToEpochSeconds(timeZoneId = "UTC"))
        assertEquals(2_147_483_648L, cborTdate.cborTDateToEpochSeconds(timeZoneId = "UTC"))
        assertEquals(expectedUtcDateTime, tdate.tDateToLocalDateTime(timeZoneId = "UTC"))
        assertEquals(expectedUtcDateTime, cborTdate.cborTDateToLocalDateTime(timeZoneId = "UTC"))
    }

    @Test
    fun fullDateTagKeepsDateOnlyAtMidnightInRequestedTimezone() {
        val fullDate = CborFullDate("2024-06-15")

        assertEquals(LocalDateTime(2024, 6, 15, 0, 0), fullDate.cborFullDateToLocalDateTime(timeZoneId = "UTC"))
        assertEquals(1_718_409_600L, fullDate.cborFullDateToEpochSeconds(timeZoneId = "UTC"))
    }

    @Test
    fun testCborFullDateToEpochSeconds() {
        val fullDate = CborFullDate("2024-01-15T00:00:00Z")
        val epochSeconds = fullDate.cborFullDateToEpochSeconds()
        assertTrue(epochSeconds > 0)
    }

    @Test
    fun testCborFullDateToEpochSecondsWithTimezone() {
        val fullDate = CborFullDate("2024-01-15T00:00:00Z")
        val epochSeconds = fullDate.cborFullDateToEpochSeconds(timeZoneId = "UTC")
        assertTrue(epochSeconds > 0)
    }

    @Test
    fun testCborTDateToLocalDateTime() {
        val tdate = CborTDate("2024-06-15T10:30:00Z")
        val localDateTime = tdate.cborTDateToLocalDateTime()
        assertNotNull(localDateTime)
    }

    @Test
    fun testCborTDateToLocalDateTimeWithTimezone() {
        val tdate = CborTDate("2024-06-15T10:30:00Z")
        val localDateTime = tdate.cborTDateToLocalDateTime(timeZoneId = "UTC")
        assertNotNull(localDateTime)
    }

    @Test
    fun testCborFullDateToLocalDateTime() {
        val fullDate = CborFullDate("2024-06-15T00:00:00Z")
        val localDateTime = fullDate.cborFullDateToLocalDateTime()
        assertNotNull(localDateTime)
    }

    @Test
    fun testCborFullDateToLocalDateTimeWithTimezone() {
        val fullDate = CborFullDate("2024-06-15T00:00:00Z")
        val localDateTime = fullDate.cborFullDateToLocalDateTime(timeZoneId = "UTC")
        assertNotNull(localDateTime)
    }

    @Test
    fun testFullDateStringToLocalDateTime() {
        val dateString: cddl_full_date = "2024-06-15T10:30:00Z"
        val localDateTime = dateString.toLocalDateTime()
        assertNotNull(localDateTime)
    }

    @Test
    fun testFullDateStringToLocalDateTimeWithTimezone() {
        val dateString: cddl_full_date = "2024-06-15T10:30:00Z"
        val localDateTime = dateString.toLocalDateTime(timeZoneId = "UTC")
        assertNotNull(localDateTime)
    }

    @Test
    fun testTDateToLocalDateTime() {
        val tdate = TDate("2024-06-15T10:30:00Z")
        val localDateTime = tdate.tDateToLocalDateTime()
        assertNotNull(localDateTime)
    }

    @Test
    fun testTDateToLocalDateTimeWithTimezone() {
        val tdate = TDate("2024-06-15T10:30:00Z")
        val localDateTime = tdate.tDateToLocalDateTime(timeZoneId = "UTC")
        assertNotNull(localDateTime)
    }

    @Test
    fun testFullDateStringToCborFullDate() {
        val dateString: cddl_full_date = "2024-06-15T10:30:00Z"
        val cborFullDate = dateString.toCborFullDate()
        assertIs<CborFullDate>(cborFullDate)
    }

    @Test
    fun testFullDateStringToCborFullDateWithTimezone() {
        val dateString: cddl_full_date = "2024-06-15T10:30:00Z"
        val cborFullDate = dateString.toCborFullDate(timeZoneId = "UTC")
        assertIs<CborFullDate>(cborFullDate)
    }

    @Test
    fun testInstantToDateStringISO() {
        val instant = Instant.fromEpochSeconds(1705363200) // 2024-01-16
        val dateString = instant.instantToDateStringISO()
        assertNotNull(dateString)
        assertTrue(dateString.contains("2024"))
    }

    @Test
    fun testInstantToDateStringISOWithTimezone() {
        val instant = Instant.fromEpochSeconds(1705363200)
        val dateString = instant.instantToDateStringISO(timeZoneId = "UTC")
        assertNotNull(dateString)
    }

    @Test
    fun testLocalDateTimeKMPToDateStringISO() {
        val localDateTime = LocalDateTimeKMP(2024, 6, 15, 10, 30, 0)
        val dateString = localDateTime.localDateToDateStringISO()
        assertNotNull(dateString)
        assertTrue(dateString.contains("2024"))
    }

    @Test
    fun testLocalDateTimeKMPToDateStringISOWithTimezone() {
        val localDateTime = LocalDateTimeKMP(2024, 6, 15, 10, 30, 0)
        val dateString = localDateTime.localDateToDateStringISO(timeZoneId = "UTC")
        assertNotNull(dateString)
    }

    @Test
    fun testLocalDateTimeToDateStringISO() {
        val localDateTime = LocalDateTime(2024, 6, 15, 10, 30, 0)
        val dateString = localDateTime.localDateTimeToDateStringISO()
        assertNotNull(dateString)
        assertTrue(dateString.contains("2024"))
    }

    @Test
    fun testLocalDateTimeToDateStringISOWithTimezone() {
        val localDateTime = LocalDateTime(2024, 6, 15, 10, 30, 0)
        val dateString = localDateTime.localDateTimeToDateStringISO(timeZoneId = "UTC")
        assertNotNull(dateString)
    }

    @Test
    fun testLocalDateToDateStringISO() {
        val localDate = LocalDate(2024, 6, 15)
        val dateString = localDate.localDateToDateStringISO()
        assertNotNull(dateString)
        assertTrue(dateString.contains("2024"))
    }

    @Test
    fun testLocalDateToDateStringISOWithTimezone() {
        val localDate = LocalDate(2024, 6, 15)
        val dateString = localDate.localDateToDateStringISO(timeZoneId = "UTC")
        assertNotNull(dateString)
    }

    @Test
    fun testLocalDateTimeKMPToCborFullDate() {
        val localDateTime = LocalDateTimeKMP(2024, 6, 15, 10, 30, 0)
        val cborFullDate = localDateTime.localDateToCborFullDate()
        assertIs<CborFullDate>(cborFullDate)
    }

    @Test
    fun testLocalDateTimeKMPToCborDate() {
        val localDateTime = LocalDateTimeKMP(2024, 6, 15, 10, 30, 0)
        val cborTDate = localDateTime.localDateTimeToCborDate()
        assertIs<CborTDate>(cborTDate)
    }

    // ========== Round-trip tests ==========

    @Test
    fun testCborTDateRoundTrip() {
        val original = CborTDate("2024-06-15T10:30:00Z")
        val encoded = Cbor.encode(original)
        val decoded = Cbor.decode<CborItem<*>>(encoded)
        assertIs<CborTagged<*>>(decoded)
    }

    @Test
    fun testCborFullDateRoundTrip() {
        val original = CborFullDate("2024-06-15")
        val encoded = Cbor.encode(original)
        val decoded = Cbor.decode<CborItem<*>>(encoded)
        assertIs<CborTagged<*>>(decoded)
    }

    // ========== Edge cases ==========

    @Test
    fun testCborTDateWithDifferentFormats() {
        // Test with local time format
        val tdate = CborTDate("2024-01-15T10:30:00")
        assertNotNull(tdate)
    }

    @Test
    fun testDateConversionConsistency() {
        val originalDateTime = LocalDateTimeKMP(2024, 6, 15, 12, 0, 0)
        val tdate = originalDateTime.localDateTimeToCborDate()
        val epochSeconds = tdate.cborTDateToEpochSeconds(timeZoneId = "UTC")
        assertTrue(epochSeconds > 0)
    }
}
