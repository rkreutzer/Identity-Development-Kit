/*
 * © 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0
 */

package com.sphereon.di

import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.job
import software.amazon.app.platform.scope.coroutine.CoroutineScopeScoped

/**
 * A child of this scoped coroutine scope whose own job is a [SupervisorJob].
 *
 * [CoroutineScopeScoped.createChild] always appends a plain `Job(parent)`, so one failed `async` or
 * `launch` in the child cancels the child, and every later coroutine started in it fails with
 * "Parent job is Cancelled" until the process restarts. Injected App, User and Session scopes are
 * shared by unrelated work within one consumer, so a single failure must stay with its own coroutine.
 * Exiting the parent scope still cancels the child.
 */
fun CoroutineScopeScoped.supervisedChild(): CoroutineScope {
    val name = coroutineContext[CoroutineName]?.name ?: "Scope"
    return CoroutineScope(coroutineContext + SupervisorJob(coroutineContext.job) + CoroutineName("$name-child"))
}
