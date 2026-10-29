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

package com.sphereon.core.api.conf

import com.sphereon.core.compat.JsExportCompat
import com.sphereon.di.HasOrder
import com.sphereon.di.Order
import com.sphereon.di.SortOrder
import com.sphereon.di.context.TenantContextData
import dev.zacsweers.metro.AppScope
import dev.zacsweers.metro.Assisted
import dev.zacsweers.metro.AssistedFactory
import dev.zacsweers.metro.AssistedInject
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding
import kotlinx.io.files.Path
import kotlin.experimental.ExperimentalObjCName
import kotlin.native.ObjCName
import kotlin.reflect.KClass

/**
 * A named source of configuration properties.
 *
 * ## Profile Contract
 *
 * Profile-aware PropertySource implementations should follow these rules:
 *
 * 1. Accept profile at construction (via `@Named("profile")` injection or constructor parameter).
 * 2. Load base configuration first, then merge profile-specific overrides on top.
 * 3. For file-based sources, use `{basename}-{profile}.{ext}` naming
 *    (e.g., `application-production.yml`). Missing profile files are silently ignored.
 * 4. For cloud-based sources, use label or tag as the profile discriminator.
 * 5. For database-based sources, use a profile column in the query filter.
 * 6. Keep logical property keys profile-free — profile selection is external to key identity.
 */
@JsExportCompat
@OptIn(ExperimentalObjCName::class)
@ObjCName("PropertySource", exact = true)
interface PropertySource<T> :
    HasOrder,
    Comparable<PropertySource<*>> {
    val isPlatformSupported: Boolean

    fun hasProperty(name: String): Boolean

    fun <T : Any> getProperty(
        name: String,
        targetType: KClass<T>,
    ): T?

    fun getPropertyAsString(name: String): String?

    fun removeProperty(name: String)

    fun getName(): String

    fun getSource(): T

    fun getAllPropertyNames(): Set<String>
}

/**
 * Property source that is explicitly scoped to a configuration level.
 *
 * This enables true scope-aware resolution (APP/TENANT/PRINCIPAL) when
 * resolving properties or interpolating `${scope:key}` placeholders.
 */
@JsExportCompat
@OptIn(ExperimentalObjCName::class)
@ObjCName("ScopedPropertySource", exact = true)
interface ScopedPropertySource<T> : PropertySource<T> {
    val configLevel: ConfigLevel
}

/**
 * Marker for property sources whose backing data can change without the source
 * being added to or removed from [PropertySources].
 *
 * Implementations should refresh synchronously from their backing source when
 * [refreshIfNeeded] is called and increment [contentRevision] whenever the
 * exposed property snapshot changes.
 */
@JsExportCompat
@OptIn(ExperimentalObjCName::class)
@ObjCName("RefreshablePropertySource", exact = true)
interface RefreshablePropertySource {
    val contentRevision: Long

    fun refreshIfNeeded()
}

/**
 * A [RefreshablePropertySource] whose snapshot can be bypassed on demand.
 *
 * [refreshIfNeeded] may keep serving a snapshot until its time-to-live ends. A caller that just
 * observed a miss for a value another process may have written moments ago uses
 * [reloadFromBackingSource] to read the backing store once more before it acts on the miss.
 * Implementations increment [contentRevision] when the reload changes the exposed properties.
 */
interface ReloadablePropertySource : RefreshablePropertySource {
    suspend fun reloadFromBackingSource()
}

/**
 * Reloads every [ReloadablePropertySource] this environment and its parents resolve from.
 *
 * This is a read-through for misses, not a refresh policy: callers invoke it only when a lookup
 * failed and a newer write may exist, then resolve again. Property reads after it observe the
 * reloaded content because the reload changes the sources' content revision.
 */
suspend fun ConfigEnvironment?.reloadFromBackingSources() {
    if (this == null) return
    for (source in getPropertySources(includeParents = true)) {
        (source.unwrappedPropertySource() as? ReloadablePropertySource)?.reloadFromBackingSource()
    }
}

/**
 * Revision of everything a [ConfigEnvironment] can resolve: the structural revision of its own
 * source set, the content revision of every [RefreshablePropertySource] in it, and the same for
 * each parent environment.
 *
 * Callers that derive an expensive value from configuration can memoize it against this number
 * and recompute only when it changes. It is the same signal
 * [CachingPropertySourcesPropertyResolver] keys its own property cache on, so a consumer keyed on
 * it is never staler than the property reads it would otherwise perform.
 */
fun ConfigEnvironment?.configContentRevision(refresh: Boolean = true): Long {
    if (this == null) return 0L
    val sources = getPropertySources(includeParents = true)
    return (sources.revision * 31L) + sources.refreshableContentRevision(refresh)
}

fun PropertySources.refreshableContentRevision(refresh: Boolean = true): Long {
    var revision = 0L
    for (source in this) {
        if (source is RefreshablePropertySource) {
            if (refresh) {
                source.refreshIfNeeded()
            }
            revision = (revision * 31L) + source.getName().hashCode().toLong()
            revision = (revision * 31L) + source.contentRevision
        }
    }
    return revision
}

/**
 * Type-safe shortcut for `getProperty(name, R::class)`: callers can write
 * `val n: Int? = src.getProperty("key")`.
 * Returns the value as generic type [R]
 */
inline fun <reified R : Any> PropertySource<*>.getProperty(name: String): R? = getProperty(name, R::class)

@JsExportCompat
abstract class AbstractPropertySource<T>(
    private val name: String,
    private val source: T,
    private val order: Int,
) : PropertySource<T> {
    protected val keyNormalizer: PropertyKeyNormalizer = PropertyKeyNormalizerImpl.Default

    override fun hasProperty(name: String): Boolean = getProperty(name, Any::class) != null

    override fun getName(): String = name

    override fun getSource(): T = source

    override fun getOrder(): Int = order

    override fun compareTo(other: PropertySource<*>): Int = this.getOrder().compareTo(other.getOrder())
}

@JsExportCompat
@OptIn(ExperimentalObjCName::class)
@ObjCName("MutableMapPropertySource", exact = true)
open class MutableMapPropertySource(
    name: String,
    source: MutableMap<String, Any> = mutableMapOf(),
    order: Int = Order.MEDIUM.orderValue,
) : AbstractPropertySource<MutableMap<String, Any>>(name, source, order) {
    override val isPlatformSupported: Boolean = true

    fun addProperties(map: Map<String, Any>) = apply { map.forEach { addProperty(it.key, it.value) } }

    fun addProperty(
        name: String,
        value: Any,
    ) = apply {
        this.getSource()[keyNormalizer.normalize(name)] = value
    }

    fun deleteProperty(name: String) = apply { getSource().remove(keyNormalizer.normalize(name)) }

    @Suppress("UNCHECKED_CAST")
    override fun <T : Any> getProperty(
        name: String,
        targetType: KClass<T>,
    ): T? {
        val value = this.getSource()[keyNormalizer.normalize(name)] ?: return null
        require(targetType.isInstance(value)) {
            "$value is not of type ${targetType.simpleName} but type ${value::class.simpleName}"
        }
        return value as T?
    }

    override fun getPropertyAsString(name: String): String? {
        val value = this.getSource()[keyNormalizer.normalize(name)] ?: return null
        return "$value"
    }

    override fun removeProperty(name: String) {
        this.getSource().remove(name)
    }

    override fun getAllPropertyNames(): Set<String> =
        this
            .getSource()
            .keys
            .map { keyNormalizer.normalize(it) }
            .toSet()
}

@JsExportCompat
@OptIn(ExperimentalObjCName::class)
@ObjCName("MapPropertySource", exact = true)
open class MapPropertySource(
    name: String,
    source: Map<String, Any>,
    order: Int = Order.MEDIUM.orderValue,
) : AbstractPropertySource<Map<String, Any>>(
        name = name,
        source = source.mapKeys { (key, _) -> PropertyKeyNormalizerImpl.Default.normalize(key) },
        order = order,
    ) {
    override val isPlatformSupported: Boolean = true

    override fun hasProperty(name: String): Boolean = getSource().keys.contains(keyNormalizer.normalize(name))

    override fun <T : Any> getProperty(
        name: String,
        targetType: KClass<T>,
    ): T? {
        val value = this.getSource()[keyNormalizer.normalize(name)] ?: return null
        require(targetType.isInstance(value)) {
            "$value is not of type ${targetType.simpleName} but type ${value::class.simpleName}"
        }
        @Suppress("UNCHECKED_CAST")
        return value as T?
    }

    override fun getPropertyAsString(name: String): String? {
        val value = this.getSource()[keyNormalizer.normalize(name)] ?: return null
        return "$value"
    }

    override fun removeProperty(name: String): Unit = throw UnsupportedOperationException("removeProperty is not supported on MapPropertySource because it's not mutable ")

    override fun getAllPropertyNames(): Set<String> =
        this
            .getSource()
            .keys
            .map { keyNormalizer.normalize(it) }
            .toSet()
}

@JsExportCompat
@AssistedFactory
interface PropertiesFilePropertySourceFactory {
    fun createPropertiesFileSource(
        name: String,
        source: Path,
    ): PropertiesFilePropertySource
}

@JsExportCompat
@AssistedInject
class PropertiesFilePropertySource(
    @Assisted name: String,
    @Assisted source: Path,
) : MapPropertySource(
        name,
        try {
            readPropertiesFromPath(source)
        } catch (_: UnsupportedOperationException) {
            emptyMap()
        },
    )

@Inject
@SingleIn(AppScope::class)
@ContributesBinding(AppScope::class)
class EnvPropertySource :
    MapPropertySource(
        name = "environment",
        source = emptyMap(), // Source is lazily populated - actual data comes from lazy fields
        order = Order.HIGHEST.orderValue,
    ) {
    // Lazy loading of normalized environment variables
    private val envMap: Map<String, Any> by lazy {
        Env.getAll().map { keyNormalizer.normalize(it.key.lowercase()) to it.value }.toMap()
    }

    // Mapping from normalized key back to original env key for fallback lookup
    private val keyMapping: Map<String, String> by lazy {
        Env.getAll().entries.associate { (key, _) -> keyNormalizer.normalize(key.lowercase()) to key }
    }

    override val isPlatformSupported: Boolean = true

    override fun hasProperty(name: String): Boolean {
        val normalizedKey = keyNormalizer.normalize(name)
        return envMap.containsKey(normalizedKey) || keyMapping.containsKey(normalizedKey)
    }

    override fun getPropertyAsString(name: String): String? = getProperty(name, String::class)

    override fun <T : Any> getProperty(
        name: String,
        targetType: KClass<T>,
    ): T? {
        val normalizedKey = keyNormalizer.normalize(name)

        // First check our lazy-loaded normalized map
        envMap[normalizedKey]?.let { return coerceFromEnvString(it, targetType) }

        // If not found, try the original env key via keyMapping
        keyMapping[normalizedKey]?.let { originalKey ->
            Env.get(originalKey)?.let { return coerceFromEnvString(it, targetType) }
        }

        // Final fallback: direct lookup (for platforms that don't support getAll)
        return (Env.get(normalizedKey) ?: Env.get(name))?.let { coerceFromEnvString(it, targetType) }
    }

    /**
     * Environment variables and `.env` file entries are always strings, but typed property reads
     * (`getProperty(key, Boolean::class)`, `Int::class`, `Long::class`, `Double::class`) expect a
     * native-typed value. Coerce the string to the requested type rather than `as T`-casting and
     * blowing up at the call site with a `ClassCastException`. Returns `null` for malformed values
     * (e.g. `getProperty("PORT", Int::class)` on `PORT=foo`) so the caller's default takes over —
     * the same behaviour as a missing key.
     */
    @Suppress("UNCHECKED_CAST")
    private fun <T : Any> coerceFromEnvString(
        value: Any,
        targetType: KClass<T>
    ): T? {
        if (targetType.isInstance(value)) {
            return value as T
        }
        val str = value as? String ?: return null
        val trimmed = str.trim()
        if (trimmed.isEmpty()) return null
        val coerced: Any? =
            when (targetType) {
                String::class -> trimmed
                Boolean::class -> trimmed.toBooleanStrictOrNull()
                Int::class -> trimmed.toIntOrNull()
                Long::class -> trimmed.toLongOrNull()
                Double::class -> trimmed.toDoubleOrNull()
                Float::class -> trimmed.toFloatOrNull()
                else -> null
            }
        return coerced as T?
    }

    override fun getAllPropertyNames(): Set<String> = envMap.keys
}

@OptIn(ExperimentalObjCName::class)
@ObjCName("StaticEnvProprtySourceObject", exact = true)
object StaticEnvPropertySourceObject : PropertySource<Map<String, Any>> by ProtectedEnvPropertySource()

@JsExportCompat
@OptIn(ExperimentalObjCName::class)
@ObjCName("PropertySources", exact = true)
interface PropertySources : MutableIterable<PropertySource<*>> {
    /**
     * Structural revision of the source set.
     *
     * Increments whenever sources are added or removed.
     */
    val revision: Long

    fun add(source: PropertySource<*>): PropertySources

    fun remove(source: PropertySource<*>): PropertySources

    fun contains(name: String): Boolean

    fun get(name: String): PropertySource<*>?

    fun copy(additionalSources: PropertySources? = null): PropertySources
}

@JsExportCompat
open class SyncedDefaultMapPropertySource(
    sourceName: String,
    private val syncLevel: ConfigLevel,
    order: Int = Order.MEDIUM.orderValue,
) : ProtectedMutableMapPropertySource(
        sourceName = sourceName,
        sourceLevel = syncLevel,
        order = order,
    ) {
    override fun addProperty(
        name: String,
        value: Any,
    ): ProtectedMutableMapPropertySource =
        apply {
            super.addProperty(name, value)
            DefaultMapPropertySourceSyncRegistry.mirrorAdd(syncLevel, name, value)
        }

    override fun addProperties(map: Map<String, Any>): ProtectedMutableMapPropertySource =
        apply {
            super.addProperties(map)
            DefaultMapPropertySourceSyncRegistry.mirrorAddAll(syncLevel, map)
        }

    override fun addProtectedProperty(
        name: String,
        value: Any,
        protection: PropertyProtection,
    ): ProtectedMutableMapPropertySource =
        apply {
            super.addProtectedProperty(name, value, protection)
            DefaultMapPropertySourceSyncRegistry.mirrorAddProtected(syncLevel, name, value, protection)
        }

    override fun deleteProperty(name: String): ProtectedMutableMapPropertySource =
        apply {
            super.deleteProperty(name)
            DefaultMapPropertySourceSyncRegistry.mirrorDelete(syncLevel, name)
        }
}

@OptIn(ExperimentalObjCName::class)
@ObjCName("DefaultAppMapPropertySource", exact = true)
object DefaultAppMapPropertySource : SyncedDefaultMapPropertySource("default-app-map", ConfigLevel.APP) {
    const val NAME = "default-app-map"
}

@OptIn(ExperimentalObjCName::class)
@ObjCName("DefaultTenantMapPropertySource", exact = true)
object DefaultTenantMapPropertySource : SyncedDefaultMapPropertySource("default-tenant-map", ConfigLevel.TENANT) {
    const val NAME = "default-tenant-map"
}

@OptIn(ExperimentalObjCName::class)
@ObjCName("DefaultPrincipalMapPropertySource", exact = true)
object DefaultPrincipalMapPropertySource : SyncedDefaultMapPropertySource("default-principal-map", ConfigLevel.PRINCIPAL) {
    const val NAME = "default-principal-map"
}

/**
 * Factory for creating isolated default mutable property sources per scope/context.
 *
 * This avoids hidden cross-context coupling from shared mutable singleton sources.
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("DefaultMapPropertySourceFactory", exact = true)
object DefaultMapPropertySourceFactory {
    fun app(): ProtectedMutableMapPropertySource =
        ProtectedMutableMapPropertySource(
            sourceName = DefaultAppMapPropertySource.NAME,
            sourceLevel = ConfigLevel.APP,
            order = Order.MEDIUM.orderValue,
        ).also {
            DefaultMapPropertySourceSyncRegistry.register(ConfigLevel.APP, it)
            it.addProperties(DefaultAppMapPropertySource.getSource())
        }

    fun tenant(): ProtectedMutableMapPropertySource =
        ProtectedMutableMapPropertySource(
            sourceName = DefaultTenantMapPropertySource.NAME,
            sourceLevel = ConfigLevel.TENANT,
            order = Order.MEDIUM.orderValue,
        ).also {
            DefaultMapPropertySourceSyncRegistry.register(ConfigLevel.TENANT, it)
            it.addProperties(DefaultTenantMapPropertySource.getSource())
        }

    fun principal(): ProtectedMutableMapPropertySource =
        ProtectedMutableMapPropertySource(
            sourceName = DefaultPrincipalMapPropertySource.NAME,
            sourceLevel = ConfigLevel.PRINCIPAL,
            order = Order.MEDIUM.orderValue,
        ).also {
            DefaultMapPropertySourceSyncRegistry.register(ConfigLevel.PRINCIPAL, it)
            it.addProperties(DefaultPrincipalMapPropertySource.getSource())
        }
}

/**
 * Internal registry that mirrors singleton default-map updates into scoped default-map sources
 * created by [DefaultMapPropertySourceFactory].
 */
internal object DefaultMapPropertySourceSyncRegistry : kotlinx.atomicfu.locks.SynchronizedObject() {
    private val appSources = mutableSetOf<ProtectedMutableMapPropertySource>()
    private val tenantSources = mutableSetOf<ProtectedMutableMapPropertySource>()
    private val principalSources = mutableSetOf<ProtectedMutableMapPropertySource>()

    fun register(
        level: ConfigLevel,
        source: ProtectedMutableMapPropertySource,
    ) {
        kotlinx.atomicfu.locks.synchronized(this) {
            sourcesFor(level).add(source)
        }
    }

    fun unregister(source: ProtectedMutableMapPropertySource) {
        kotlinx.atomicfu.locks.synchronized(this) {
            appSources.remove(source)
            tenantSources.remove(source)
            principalSources.remove(source)
        }
    }

    fun clear(level: ConfigLevel) {
        kotlinx.atomicfu.locks.synchronized(this) {
            sourcesFor(level).clear()
        }
    }

    fun mirrorAdd(
        level: ConfigLevel,
        name: String,
        value: Any,
    ) {
        kotlinx.atomicfu.locks.synchronized(this) {
            sourcesFor(level).forEach { it.addProperty(name, value) }
        }
    }

    fun mirrorAddAll(
        level: ConfigLevel,
        map: Map<String, Any>,
    ) {
        kotlinx.atomicfu.locks.synchronized(this) {
            sourcesFor(level).forEach { it.addProperties(map) }
        }
    }

    fun mirrorAddProtected(
        level: ConfigLevel,
        name: String,
        value: Any,
        protection: PropertyProtection,
    ) {
        kotlinx.atomicfu.locks.synchronized(this) {
            sourcesFor(level).forEach { it.addProtectedProperty(name, value, protection) }
        }
    }

    fun mirrorDelete(
        level: ConfigLevel,
        name: String,
    ) {
        kotlinx.atomicfu.locks.synchronized(this) {
            sourcesFor(level).forEach { it.deleteProperty(name) }
        }
    }

    private fun sourcesFor(level: ConfigLevel): MutableSet<ProtectedMutableMapPropertySource> =
        when (level) {
            ConfigLevel.APP -> appSources
            ConfigLevel.TENANT -> tenantSources
            ConfigLevel.PRINCIPAL -> principalSources
        }
}

@Inject
@SingleIn(AppScope::class)
@ContributesBinding(AppScope::class, binding = binding<PropertySources>())
@OptIn(ExperimentalObjCName::class)
@ObjCName("AppPropertySourcesImpl", exact = true)
class AppPropertySourcesImpl :
    DefaultPropertySources(
        sources = mutableListOf(StaticProtectedEnvPropertySourceObject, DefaultMapPropertySourceFactory.app()),
        sorting = SortOrder.ASC,
    )

@Inject
@SingleIn(TenantContextData::class)
@ContributesBinding(TenantContextData::class, binding = binding<PropertySources>())
@OptIn(ExperimentalObjCName::class)
@ObjCName("TenantPropertySourcesImpl", exact = true)
class TenantPropertySourcesImpl :
    DefaultPropertySources(
        sources = mutableListOf(StaticProtectedEnvPropertySourceObject, DefaultMapPropertySourceFactory.tenant()),
        sorting = SortOrder.ASC,
    )

@Inject
open class DefaultPropertySources(
    sources: MutableList<PropertySource<*>> = mutableListOf(),
    val sorting: SortOrder = SortOrder.ASC,
) : kotlinx.atomicfu.locks.SynchronizedObject(),
    PropertySources {
    private var sources = mutableListOf(*sources.toTypedArray())
    private var _revision: Long = 0L
    private var dirty: Boolean = true

    override val revision: Long
        get() = kotlinx.atomicfu.locks.synchronized(this) { _revision }

    init {
        sources.forEach(::validatePropertySourceEnvironmentReferencesForWrite)
        sort()
        _revision = 1L
    }

    override fun add(source: PropertySource<*>) =
        apply {
            validatePropertySourceEnvironmentReferencesForWrite(source)
            kotlinx.atomicfu.locks.synchronized(this@DefaultPropertySources) {
                sources.add(source)
                dirty = true
                sort()
                incrementRevision()
            }
        }

    override fun remove(source: PropertySource<*>): PropertySources =
        apply {
            kotlinx.atomicfu.locks.synchronized(this@DefaultPropertySources) {
                if (sources.remove(source)) {
                    dirty = true
                    sort()
                    incrementRevision()
                }
            }
        }

    override fun copy(additionalSources: PropertySources?): PropertySources {
        val ownSnapshot = snapshotForCopy()
        // Snapshot collections independently. Neither another collection's monitor nor a scoped
        // source's lazy validation/loading may be entered while this collection is locked.
        val additionalSnapshot =
            when {
                additionalSources == null -> null
                additionalSources === this -> ownSnapshot
                additionalSources is DefaultPropertySources -> additionalSources.snapshotForCopy()
                else -> additionalSources.toList() to additionalSources.revision
            }
        return DefaultPropertySources(
            sources = (ownSnapshot.first + additionalSnapshot?.first.orEmpty()).toMutableList(),
            sorting = sorting,
        ).also { copiedSources ->
            copiedSources._revision =
                additionalSnapshot?.let { (ownSnapshot.second * 31L) + it.second }
                    ?: ownSnapshot.second
        }
    }

    private fun snapshotForCopy(): Pair<List<PropertySource<*>>, Long> =
        kotlinx.atomicfu.locks.synchronized(this) { sources.toList() to _revision }

    fun removeByName(name: String): Boolean =
        kotlinx.atomicfu.locks.synchronized(this) {
            val removed = get(name)?.let { sources.remove(it) } ?: false
            if (removed) {
                dirty = true
                sort()
                incrementRevision()
            }
            removed
        }

    override fun contains(name: String): Boolean =
        kotlinx.atomicfu.locks.synchronized(this) {
            sources.any { it.getName() == name }
        }

    override fun get(name: String): PropertySource<*>? =
        kotlinx.atomicfu.locks.synchronized(this) {
            sources.firstOrNull { it.getName() == name }
        }

    override fun iterator(): MutableIterator<PropertySource<*>> =
        kotlinx.atomicfu.locks.synchronized(this) {
            sort()
            sources.toMutableList().iterator()
        }

    private fun sort() {
        if (!dirty) {
            return
        }
        when (sorting) {
            SortOrder.ASC -> {
                this.sources = sources.sortedWith(naturalOrder()).toMutableList()
            }

            SortOrder.DESC -> {
                this.sources = sources.sortedWith(reverseOrder()).toMutableList()
            }

            else -> { /* NONE: keep insertion order, no copy needed */ }
        }
        dirty = false
    }

    private fun incrementRevision() {
        _revision++
    }
}
