/*
 * Copyright 2026 Sphereon International B.V.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sphereon.ktor.server.inject

import com.sphereon.core.api.http.GenericHttpRequest
import com.sphereon.core.api.http.GenericHttpBody
import com.sphereon.core.api.http.GenericHttpResponse
import com.sphereon.core.api.http.dispatch.HttpAdapterDispatcher
import com.sphereon.core.api.http.dispatch.HttpAdapterRouteMatch
import com.sphereon.core.api.session.CommandInvocationBoundary
import com.sphereon.core.api.session.CommandInvocationContext
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.toList
import kotlin.test.Test
import kotlin.test.assertEquals

class UniversalHttpInvocationBoundaryTest {
    @Test
    fun universalIngressMarksTheFirstCommandExternal() = runTest { assertExternalRoot() }

    @Test
    fun universalIngressResetsAnExistingCommandTree() = runTest {
        withContext(CommandInvocationContext.externalCommand()) { assertExternalRoot() }
    }

    @Test
    fun lazyInlineHttpBodyRetainsExternalBoundaryDuringCollection() = runTest {
        var seen: CommandInvocationContext? = null
        val response = dispatchUniversalHttpRequest(
            object : HttpAdapterDispatcher {
                override suspend fun dispatch(request: GenericHttpRequest, route: HttpAdapterRouteMatch) =
                    GenericHttpResponse.withTextStreamBody(statusCode = 200, flow = flow {
                        seen = currentCoroutineContext()[CommandInvocationContext]
                        emit("chunk")
                    })
            },
            GenericHttpRequest(method = "GET", path = "/test"),
            HttpAdapterRouteMatch(adapterId = "test.stream", method = "GET", originalPath = "/test", normalizedPath = "/test",
                matchedPathPattern = "/test", handlerCommandId = "test.stream.get", tenantIdFromPath = null),
        )
        assertEquals(listOf("chunk"), (response.bodyContent as GenericHttpBody.TextStream).flow.toList())
        assertEquals(CommandInvocationBoundary.EXTERNAL, seen?.boundary)
        assertEquals(-1, seen?.commandDepth)
    }

    private suspend fun assertExternalRoot() {
        var seen: CommandInvocationContext? = null
        val response = dispatchUniversalHttpRequest(
            dispatcher = object : HttpAdapterDispatcher {
                override suspend fun dispatch(request: GenericHttpRequest, route: HttpAdapterRouteMatch): GenericHttpResponse {
                    seen = currentCoroutineContext()[CommandInvocationContext]
                    return GenericHttpResponse(statusCode = 200, body = "accepted")
                }
            },
            request = GenericHttpRequest(method = "GET", path = "/test"),
            route = HttpAdapterRouteMatch(
                adapterId = "test.boundary",
                method = "GET",
                originalPath = "/test",
                normalizedPath = "/test",
                matchedPathPattern = "/test",
                handlerCommandId = "test.boundary.get",
                tenantIdFromPath = null,
            ),
        )
        assertEquals(200, response.statusCode)
        assertEquals(CommandInvocationBoundary.EXTERNAL, seen?.boundary)
        assertEquals(-1, seen?.commandDepth)
        val command = CommandInvocationContext.enteredFrom(seen)
        assertEquals(0, command.commandDepth)
        assertEquals(CommandInvocationBoundary.EXTERNAL, command.boundary)
    }
}
