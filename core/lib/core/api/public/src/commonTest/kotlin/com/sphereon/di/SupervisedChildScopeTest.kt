/*
 * © 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0
 */

package com.sphereon.di

import com.sphereon.di.app.AppScopedProviders
import com.sphereon.di.context.UserContextScopedProviders
import com.sphereon.di.session.SessionScopedProviders
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.isActive
import kotlinx.coroutines.test.runTest
import software.amazon.app.platform.scope.Scoped
import software.amazon.app.platform.scope.coroutine.CoroutineScopeScoped
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * One failed coroutine in an injected App, User or Session scope must not cancel the scope for the
 * rest of the process. A non-supervising child did exactly that: the platform's tenant signing-key
 * database router kept failing with "Parent job is Cancelled" for every tenant it had not cached yet.
 */
class SupervisedChildScopeTest {
    private val appProviders = object : AppScopedProviders {
        override fun appScopedSet(): Set<Scoped> = emptySet()
    }
    private val userProviders = object : UserContextScopedProviders {
        override fun userScopedSet(): Set<Scoped> = emptySet()
    }
    private val sessionProviders = object : SessionScopedProviders {
        override fun sessionScopedSet(): Set<Scoped> = emptySet()
    }

    @Test
    fun appScopeSurvivesAFailedCoroutine() = runTest {
        val scoped = appProviders.provideIdkAppScopeCoroutineScopeScoped(Dispatchers.Default)
        assertSurvivesFailure(appProviders.provideIdkAppCoroutineScope(scoped))
        scoped.onExitScope()
    }

    @Test
    fun userScopeSurvivesAFailedCoroutine() = runTest {
        val scoped = userProviders.provideContextScopeCoroutineScopeScoped(Dispatchers.Default)
        assertSurvivesFailure(userProviders.provideContextCoroutineScope(scoped))
        scoped.onExitScope()
    }

    @Test
    fun sessionScopeSurvivesAFailedCoroutine() = runTest {
        val scoped = sessionProviders.provideSessionScopeCoroutineScopeScoped(Dispatchers.Default)
        assertSurvivesFailure(sessionProviders.provideSessionCoroutineScope(scoped))
        scoped.onExitScope()
    }

    @Test
    fun exitingTheParentScopeStillCancelsTheSupervisedChild() = runTest {
        val scoped = appProviders.provideIdkAppScopeCoroutineScopeScoped(Dispatchers.Default)
        val child = appProviders.provideIdkAppCoroutineScope(scoped)
        assertTrue(child.isActive)

        scoped.onExitScope()

        assertFalse(child.isActive, "The child belongs to the scope's lifetime")
    }

    /** The hazard the providers avoid: a plain createChild() stays cancelled after one failure. */
    @Test
    fun aPlainCreatedChildIsPoisonedByOneFailure() = runTest {
        val scoped = appProviders.provideIdkAppScopeCoroutineScopeScoped(Dispatchers.Default)
        val plain = scoped.createChild()

        val failed = runCatching { plain.async { error("resolution failed") }.await() }
        assertIs<IllegalStateException>(failed.exceptionOrNull())

        val next = runCatching { plain.async { 42 }.await() }
        assertIs<CancellationException>(next.exceptionOrNull())
        scoped.onExitScope()
    }

    private suspend fun assertSurvivesFailure(scope: CoroutineScope) {
        val failed = runCatching { scope.async { error("resolution failed") }.await() }
        assertIs<IllegalStateException>(failed.exceptionOrNull())
        assertTrue(scope.isActive, "One failed coroutine must not cancel the shared scope")

        assertEquals(42, scope.async { 42 }.await(), "Later unrelated work still runs")
    }
}
