/*
 * Copyright 2023-2026 Sphereon International B.V.
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

package com.sphereon.sdjwt.vc

import com.sphereon.core.compat.JsExportCompat
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.statement.readRawBytes
import io.ktor.http.isSuccess
import kotlinx.serialization.json.Json

/**
 * Service for resolving SD-JWT-VC type metadata
 *
 * Type metadata describes the structure, claims, and display properties
 * of a verifiable credential type.
 *
 * Resolution strategies:
 * 1. URL-based: VCT is HTTPS URL pointing to metadata
 * 2. Registry-based: VCT is identifier, lookup in trusted registry
 * 3. Cache-based: Previously resolved metadata
 */
@JsExportCompat
interface TypeMetadataResolver {
    /**
     * Resolve type metadata for the given VCT
     *
     * @param vct Verifiable Credential Type identifier
     * @return Resolution result (success or failure)
     */
    suspend fun resolve(vct: String): TypeMetadataResolutionResult

    /**
     * Check if this resolver supports the given VCT format
     *
     * @param vct Verifiable Credential Type identifier
     * @return True if this resolver can handle the VCT
     */
    fun supports(vct: String): Boolean
}

/**
 * URL-based type metadata resolver
 * Resolves metadata by fetching from HTTPS URLs
 *
 * @property httpClient Ktor HTTP client for fetching metadata
 * @property json JSON serializer
 */
class UrlTypeMetadataResolver(
    private val httpClient: HttpClient,
    private val json: Json = Json { ignoreUnknownKeys = true },
) : TypeMetadataResolver {
    override suspend fun resolve(vct: String): TypeMetadataResolutionResult {
        if (!supports(vct)) {
            return TypeMetadataResolutionResult.Failure(
                TypeMetadataResolutionError.UnsupportedVct(vct),
            )
        }

        return try {
            val response = httpClient.get(vct)

            if (!response.status.isSuccess()) {
                return when (response.status.value) {
                    404 -> {
                        TypeMetadataResolutionResult.Failure(TypeMetadataResolutionError.NotFound)
                    }

                    else -> {
                        TypeMetadataResolutionResult.Failure(
                            TypeMetadataResolutionError.NetworkError(
                                "HTTP ${response.status.value}: ${response.status.description}",
                            ),
                        )
                    }
                }
            }

            val body = response.readRawBytes()
            if (body.isEmpty()) {
                return TypeMetadataResolutionResult.Failure(
                    TypeMetadataResolutionError.InvalidFormat("Empty response body"),
                )
            }

            val metadata = json.decodeFromString<SdJwtVcTypeMetadata>(body.decodeToString())
            TypeMetadataResolutionResult.Success(metadata, body)
        } catch (expected: Exception) {
            TypeMetadataResolutionResult.Failure(
                TypeMetadataResolutionError.NetworkError(
                    message = "Failed to resolve type metadata: ${expected.message}",
                    cause = expected,
                ),
            )
        }
    }

    override fun supports(vct: String): Boolean = vct.startsWith("https://", ignoreCase = true)
}

/**
 * In-memory cache for type metadata
 * Reduces network requests by caching previously resolved metadata
 *
 * @property delegate Underlying resolver (e.g., UrlTypeMetadataResolver)
 * @property maxSize Maximum cache entries (default: 100)
 */
class CachedTypeMetadataResolver(
    private val delegate: TypeMetadataResolver,
    private val maxSize: Int = 100,
) : TypeMetadataResolver {
    private val cache = mutableMapOf<String, TypeMetadataResolutionResult.Success>()

    override suspend fun resolve(vct: String): TypeMetadataResolutionResult {
        // Check cache first
        cache[vct]?.let { cached ->
            return cached
        }

        // Delegate to underlying resolver
        val result = delegate.resolve(vct)

        // Cache successful results
        if (result is TypeMetadataResolutionResult.Success) {
            // Simple LRU: remove oldest if cache is full
            if (cache.size >= maxSize) {
                val firstKey = cache.keys.first()
                cache.remove(firstKey)
            }
            cache[vct] = result
        }

        return result
    }

    override fun supports(vct: String): Boolean = delegate.supports(vct)

    /**
     * Clear all cached metadata
     */
    fun clear() {
        cache.clear()
    }

    /**
     * Remove specific VCT from cache
     */
    fun evict(vct: String) {
        cache.remove(vct)
    }
}

/**
 * Composite resolver that tries multiple resolvers in order
 *
 * @property resolvers List of resolvers to try (in order)
 */
class CompositeTypeMetadataResolver(
    private val resolvers: List<TypeMetadataResolver>,
) : TypeMetadataResolver {
    override suspend fun resolve(vct: String): TypeMetadataResolutionResult {
        for (resolver in resolvers) {
            if (resolver.supports(vct)) {
                val result = resolver.resolve(vct)
                if (result is TypeMetadataResolutionResult.Success) {
                    return result
                }
                // Continue to next resolver on failure
            }
        }

        return TypeMetadataResolutionResult.Failure(
            TypeMetadataResolutionError.UnsupportedVct(vct),
        )
    }

    override fun supports(vct: String): Boolean = resolvers.any { it.supports(vct) }
}

/**
 * Static/pre-configured type metadata resolver
 * Useful for testing or offline scenarios
 *
 * @property metadata Map of VCT to pre-configured metadata
 * @property rawDocuments Optional original documents per VCT. Each must decode to the metadata registered
 * for the same VCT, and is then the representation an `#integrity` expression is verified against.
 */
class StaticTypeMetadataResolver(
    private val metadata: Map<String, SdJwtVcTypeMetadata>,
    rawDocuments: Map<String, ByteArray> = emptyMap(),
) : TypeMetadataResolver {
    private val rawDocuments: Map<String, ByteArray> = rawDocuments.mapValues { it.value.copyOf() }

    init {
        val json = Json { ignoreUnknownKeys = true }
        for ((vct, raw) in this.rawDocuments) {
            val registered = requireNotNull(metadata[vct]) { "Raw document supplied for unregistered vct '$vct'" }
            require(json.decodeFromString<SdJwtVcTypeMetadata>(raw.decodeToString()) == registered) {
                "Raw document for vct '$vct' does not decode to the registered metadata"
            }
        }
    }

    override suspend fun resolve(vct: String): TypeMetadataResolutionResult {
        val found = metadata[vct]
        return if (found != null) {
            TypeMetadataResolutionResult.Success(found, rawDocuments[vct])
        } else {
            TypeMetadataResolutionResult.Failure(TypeMetadataResolutionError.NotFound)
        }
    }

    override fun supports(vct: String): Boolean = metadata.containsKey(vct)
}

/**
 * Validates that there are no circular dependencies in the type extends chain
 * Per draft-13 §7.2.3, circular type dependencies MUST be rejected
 *
 * @param vct The VCT to validate
 * @param resolver The resolver to use for fetching metadata
 * @param visited Set of already visited VCTs (for cycle detection)
 * @return Validation result (error if circular dependency found)
 */
suspend fun validateTypeExtendsChain(
    vct: String,
    resolver: TypeMetadataResolver,
    visited: MutableSet<String> = mutableSetOf(),
): TypeMetadataResolutionResult? {
    // Check for circular dependency
    if (vct in visited) {
        return TypeMetadataResolutionResult.Failure(
            TypeMetadataResolutionError.CircularDependency(
                vct = vct,
                chain = visited.toList() + vct,
            ),
        )
    }

    visited.add(vct)

    // Resolve current VCT metadata
    val result = resolver.resolve(vct)
    if (result is TypeMetadataResolutionResult.Failure) {
        return result
    }

    // Check if there's an extends field
    val metadata = (result as TypeMetadataResolutionResult.Success).metadata
    val extendsVct = metadata.extends

    if (extendsVct != null) {
        // Recursively validate the parent type
        val parentValidation = validateTypeExtendsChain(extendsVct, resolver, visited)
        if (parentValidation != null) {
            return parentValidation
        }
    }

    // No circular dependency found
    return null
}
