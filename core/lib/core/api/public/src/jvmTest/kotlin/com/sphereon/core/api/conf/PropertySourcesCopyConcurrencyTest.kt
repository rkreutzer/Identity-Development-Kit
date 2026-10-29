package com.sphereon.core.api.conf

import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertSame

class PropertySourcesCopyConcurrencyTest {
    private class LazyScopedSource : MutableMapPropertySource("lazy-scoped", mutableMapOf("value" to "safe")),
        ScopedPropertySource<MutableMap<String, Any>> {
        override val configLevel = ConfigLevel.TENANT
        var beforeEnumeration: (() -> Unit)? = null

        override fun getAllPropertyNames(): Set<String> {
            beforeEnumeration?.invoke()
            return super.getAllPropertyNames()
        }
    }

    @Test
    fun lazyValidationCanReadCollectionRevisionOnAnotherThreadWhileOuterLifecycleLockIsHeld() {
        val source = LazyScopedSource()
        val sources = DefaultPropertySources(mutableListOf(source))
        val loader = Executors.newSingleThreadExecutor()
        val outerLifecycleLock = Any()
        try {
            source.beforeEnumeration = {
                assertEquals(sources.revision, loader.submit<Long> { sources.revision }.get(5, TimeUnit.SECONDS))
            }
            val copied = synchronized(outerLifecycleLock) { sources.copy() }
            assertSame(source, copied.get("lazy-scoped"))
            assertEquals(sources.revision, copied.revision)
        } finally {
            loader.shutdownNow()
            check(loader.awaitTermination(5, TimeUnit.SECONDS))
        }
    }

    @Test
    fun additionalSourceValidationCanReadBothCollectionRevisionsOnAnotherThread() {
        val sources = DefaultPropertySources()
        val source = LazyScopedSource()
        val additional = DefaultPropertySources(mutableListOf(source))
        val loader = Executors.newSingleThreadExecutor()
        try {
            source.beforeEnumeration = {
                loader.submit<Long> { sources.revision + additional.revision }.get(5, TimeUnit.SECONDS)
            }
            val copied = sources.copy(additional)
            assertSame(source, copied.get("lazy-scoped"))
            assertEquals(sources.revision * 31L + additional.revision, copied.revision)
        } finally {
            loader.shutdownNow()
            check(loader.awaitTermination(5, TimeUnit.SECONDS))
        }
    }

    @Test
    fun copyingStillRejectsScopedEnvironmentReferencesIntroducedAfterRegistration() {
        val source = LazyScopedSource()
        val sources = DefaultPropertySources(mutableListOf(source))
        source.addProperty("forbidden", "\${env:PATH}")
        assertFailsWith<IllegalArgumentException> { sources.copy() }
        assertSame(source, sources.get("lazy-scoped"))
    }

    @Test
    fun copyingSnapshotsMembershipAndPreservesSharedSourcesAndCombinedRevision() {
        val source = LazyScopedSource()
        val sources = DefaultPropertySources(mutableListOf(source))
        val additional = DefaultPropertySources(mutableListOf(MapPropertySource("additional", mapOf("extra" to "value"))))
        val revision = sources.revision * 31L + additional.revision
        val copied = sources.copy(additional)
        sources.add(MapPropertySource("later", emptyMap()))
        additional.removeByName("additional")
        assertEquals(listOf("lazy-scoped", "additional"), copied.map { it.getName() })
        assertSame(source, copied.get("lazy-scoped"))
        assertEquals(revision, copied.revision)
        val selfCopy = sources.copy(sources)
        assertEquals(sources.revision * 32L, selfCopy.revision)
        assertEquals(sources.count() * 2, selfCopy.count())
    }
}
