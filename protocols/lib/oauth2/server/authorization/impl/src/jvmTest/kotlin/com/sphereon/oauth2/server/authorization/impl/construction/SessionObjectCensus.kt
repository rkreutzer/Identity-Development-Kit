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
 */

package com.sphereon.oauth2.server.authorization.impl.construction

import com.sphereon.core.api.context.ContextConfig
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.log.SessionLogService
import com.sphereon.di.app.AppGraph
import com.sphereon.di.context.UserContextGraph
import com.sphereon.di.session.SessionContext
import com.sphereon.di.session.SessionGraph
import com.sphereon.di.session.SessionInstance
import dev.zacsweers.metro.AppScope
import dev.zacsweers.metro.Provider
import dev.zacsweers.metro.SingleIn
import java.lang.reflect.Modifier
import java.util.IdentityHashMap

/**
 * Counts the objects a resolved session binding holds on to, as a stand-in for what resolving it
 * constructed.
 *
 * The walk follows instance fields of Sphereon classes and the elements of collections, maps and
 * arrays. It stops at an uninitialized [Lazy] or a [Provider], since those are the points where
 * construction is deferred, and follows an initialized [Lazy] into its value. It also stops at
 * the shared session infrastructure (execution, context, logging, configuration, the graphs
 * themselves), which every request has already built, and at `@SingleIn(AppScope::class)`
 * classes, which are built once per application rather than per request. Those are listed but
 * not counted as per-request objects.
 */
internal class SessionObjectCensus private constructor(
    /** Per-request Sphereon objects reachable from the root, by class name. */
    val perRequest: Map<String, Int>,
    /** Application singletons reachable from the root, by class name. */
    val appSingletons: Set<String>,
    private val reached: List<Any>,
) {
    val perRequestCount: Int get() = perRequest.values.sum()

    fun reachesInstanceOf(type: Class<*>): Boolean = reached.any { type.isInstance(it) }

    fun describe(label: String): String =
        buildString {
            appendLine("$label: $perRequestCount per-request objects, ${appSingletons.size} app singletons")
            perRequest.entries.sortedWith(compareBy({ -it.value }, { it.key })).forEach { (name, count) ->
                appendLine("  $count x $name")
            }
            appSingletons.sorted().forEach { appendLine("  app: $it") }
        }

    companion object {
        private val sharedInfrastructure =
            listOf(
                SessionExecution::class.java,
                SessionContext::class.java,
                SessionInstance::class.java,
                SessionGraph::class.java,
                UserContextGraph::class.java,
                AppGraph::class.java,
                ContextConfig::class.java,
                SessionLogService::class.java,
            )

        fun of(root: Any): SessionObjectCensus {
            val visited = IdentityHashMap<Any, Unit>()
            val perRequest = mutableMapOf<String, Int>()
            val appSingletons = mutableSetOf<String>()
            val reached = mutableListOf<Any>()
            val pending = ArrayDeque<Any>()
            pending.add(root)
            while (pending.isNotEmpty()) {
                val current = pending.removeLast()
                if (visited.put(current, Unit) != null) continue
                when {
                    current is Lazy<*> -> if (current.isInitialized()) current.value?.let(pending::add)
                    current is Provider<*> -> Unit
                    current is Map<*, *> -> current.values.forEach { it?.let(pending::add) }
                    current is Iterable<*> -> current.forEach { it?.let(pending::add) }
                    current is Array<*> -> current.forEach { it?.let(pending::add) }
                    !current.javaClass.name.startsWith("com.sphereon.") -> Unit
                    sharedInfrastructure.any { it.isInstance(current) } -> Unit
                    current.isAppSingleton() -> {
                        appSingletons += current.javaClass.name
                        reached += current
                    }
                    else -> {
                        perRequest.merge(current.javaClass.name, 1, Int::plus)
                        reached += current
                        current.referencedObjects().forEach(pending::add)
                    }
                }
            }
            return SessionObjectCensus(perRequest, appSingletons, reached)
        }

        private fun Any.isAppSingleton(): Boolean = javaClass.getAnnotation(SingleIn::class.java)?.scope == AppScope::class

        private fun Any.referencedObjects(): List<Any> {
            val values = mutableListOf<Any>()
            var type: Class<*>? = javaClass
            while (type != null && type != Any::class.java) {
                for (field in type.declaredFields) {
                    if (Modifier.isStatic(field.modifiers) || field.type.isPrimitive) continue
                    val value = runCatching { field.isAccessible = true; field.get(this) }.getOrNull() ?: continue
                    values += value
                }
                type = type.superclass
            }
            return values
        }
    }
}
