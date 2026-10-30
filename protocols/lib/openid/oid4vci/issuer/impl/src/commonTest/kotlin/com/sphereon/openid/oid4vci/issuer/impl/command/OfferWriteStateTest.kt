/*
 * Copyright 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

package com.sphereon.openid.oid4vci.issuer.impl.command

import com.sphereon.core.api.error.IdkError
import com.sphereon.openid.oid4vci.issuer.command.markNothingWritten
import com.sphereon.openid.oid4vci.issuer.command.nothingWritten
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class OfferWriteStateTest {
    @Test
    fun shouldNotMarkAnErrorByItsCode() {
        assertFalse(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "refused").nothingWritten)
        assertFalse(IdkError.INVALID_STATE(message = "refused").nothingWritten)
    }

    @Test
    fun shouldKeepEverythingButTheMarkerWhenMarkingAnError() {
        val original = IdkError.ILLEGAL_ARGUMENT_ERROR(message = "refused")

        val marked = original.markNothingWritten()

        assertTrue(marked.nothingWritten)
        assertEquals(original.code, marked.code)
        assertEquals(original.message, marked.message)
        assertEquals(original.category, marked.category)
        assertEquals(original.severity, marked.severity)
    }
}
