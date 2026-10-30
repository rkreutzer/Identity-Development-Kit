/*
 * (c) 2026 Sphereon International B.V.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sphereon.oauth2.server.authorization.impl.time

import dev.zacsweers.metro.AppScope
import dev.zacsweers.metro.ContributesTo
import dev.zacsweers.metro.Named
import dev.zacsweers.metro.Provides
import dev.zacsweers.metro.SingleIn
import kotlin.time.Clock
import kotlin.time.Instant
import kotlin.time.TimeSource

/** Qualifier for clocks used to expire short-lived, server-issued opaque artifacts. */
internal const val OAUTH2_ARTIFACT_CLOCK = com.sphereon.oauth2.server.authorization.time.OAUTH2_ARTIFACT_CLOCK

/**
 * A wall-clock-compatible clock whose elapsed time cannot move backwards while the process runs.
 *
 * Authorization codes and PAR request URIs express absolute expiry instants in their storage
 * contracts, but their security lifetime is relative to issuance. Anchoring an instant once and
 * advancing it from the platform monotonic source prevents a backwards NTP/VM clock correction
 * from extending those lifetimes. A process restart deliberately re-anchors to the current wall
 * clock so persisted absolute instants remain meaningful.
 */
internal class MonotonicOAuth2ArtifactClock(
    wallClock: Clock = Clock.System,
    private val timeSource: TimeSource.WithComparableMarks = TimeSource.Monotonic,
) : Clock {
    // The mark is taken before the wall clock is read, so this clock is never behind the wall clock by the gap between the two reads.
    // Instants stamped from the wall clock, such as a session's creation time, then never lie in this clock's future.
    private val anchorMark = timeSource.markNow()
    private val anchorInstant = wallClock.now()

    override fun now(): Instant = anchorInstant + anchorMark.elapsedNow()
}

@ContributesTo(AppScope::class)
interface OAuth2ArtifactClockModule {
    @Provides
    @SingleIn(AppScope::class)
    @Named(OAUTH2_ARTIFACT_CLOCK)
    fun provideOAuth2ArtifactClock(): Clock = MonotonicOAuth2ArtifactClock()
}
