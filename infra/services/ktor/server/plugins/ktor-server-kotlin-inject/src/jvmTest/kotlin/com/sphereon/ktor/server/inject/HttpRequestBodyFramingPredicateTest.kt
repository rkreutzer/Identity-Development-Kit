package com.sphereon.ktor.server.inject

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class HttpRequestBodyFramingPredicateTest {
    @Test
    fun unknownLengthHttp2AndHttp3BodiesRemainReadableWithoutConnectionHeaderSemantics() {
        assertTrue(resolveHttpRequestBodyFraming("HTTP/2.0", emptyList(), emptyList()).shouldReadBody)
        assertTrue(resolveHttpRequestBodyFraming("HTTP/3.0", emptyList(), emptyList()).shouldReadBody)
        assertFalse(resolveHttpRequestBodyFraming("HTTP/1.0", emptyList(), emptyList()).shouldReadBody)
        assertFalse(resolveHttpRequestBodyFraming("HTTP/1.1", emptyList(), emptyList()).shouldReadBody)
        assertTrue(resolveHttpRequestBodyFraming("HTTP/1.1", emptyList(), listOf("chunked")).shouldReadBody)
        assertTrue(resolveHttpRequestBodyFraming("HTTP/1.1", listOf("5"), emptyList()).shouldReadBody)
        assertTrue(resolveHttpRequestBodyFraming("HTTP/1.1", listOf("5"), emptyList()).shouldReadBody)
        assertFalse(resolveHttpRequestBodyFraming("HTTP/1.1", listOf("0"), emptyList()).shouldReadBody)
    }

    @Test
    fun malformedOrAmbiguousFramingFailsBeforeBodyRead() {
        val bad = listOf(
            Triple("HTTP/1.1", listOf("2x"), emptyList()),
            Triple("HTTP/1.1", listOf("0"), listOf("chunked")),
            Triple("HTTP/1.1", emptyList(), listOf("gzip")),
            Triple("HTTP/1.1", listOf("0", "0"), emptyList()),
            Triple("HTTP/1.0", emptyList(), listOf("chunked")),
        )
        bad.forEach { (version, lengths, codings) ->
            val rejected = runCatching {
                resolveHttpRequestBodyFraming(version, lengths, codings)
            }.exceptionOrNull()
            assertTrue(rejected is InvalidHttpRequestFramingException)
        }
    }

    @Test
    fun supportedIdentityAndFinalChunkedListsRemainReadable() {
        for (fields in listOf(listOf("identity, ChUnKeD"), listOf("identity", "chunked"), listOf(" identity ", "\tCHUNKED\t"))) {
            val framing = resolveHttpRequestBodyFraming("HTTP/1.1", emptyList(), fields)
            assertTrue(framing.shouldReadBody)
            kotlin.test.assertEquals(null, framing.contentLength)
        }
    }

    @Test
    fun malformedTransferCodingListsStillFailClosed() {
        for (fields in listOf(listOf("chunked", "chunked"), listOf("chunked, identity"), listOf("identity"), listOf("identity,,chunked"), listOf(",chunked"), listOf("identity, chunked,"), listOf("gzip, chunked"), listOf("identity; q=1, chunked"))) {
            val failure = runCatching { resolveHttpRequestBodyFraming("HTTP/1.1", emptyList(), fields) }.exceptionOrNull()
            assertTrue(failure is InvalidHttpRequestFramingException)
        }
    }
}
