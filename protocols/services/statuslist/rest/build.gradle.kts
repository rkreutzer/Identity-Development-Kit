/*
 * PUBLIC, unauthenticated, cacheable REST surface that hosts the signed credential status-list
 * token (`<basePath>/{id}` and `<basePath>/by/{correlationId}`). This is the URI a verifier
 * resolves: the endpoints return the RAW signed token string with the token's own media type
 * (`application/statuslist+jwt` / `application/statuslist+cwt` / `application/vc+jwt`) and a
 * `Cache-Control` header derived from the token TTL — never a JSON envelope.
 *
 * Lives on the IDK services side (open core): hosting a status list is a basic capability every
 * deployment should have, and other IDK REST API implementations live here too. Thin
 * `HttpEndpointCommand` impls + a `CommandBackedHttpAdapter` + descriptor provider delegating to
 * the IDK `GetStatusListTokenCommand` (`statuslist.token.get`). Split from the EDK admin/business-key
 * management surface (`lib-statuslist-management-rest`) so a deployment may host the public token
 * without exposing the management CRUD surface.
 *
 * The shared `common-components.yml` is synced next to this module's openapi.yml by the conventions
 * plugin (so the spec keeps clean `./common-components.yml#/...` references).
 */
plugins {
    alias(sphereonplug.plugins.org.jetbrains.kotlin.multiplatform)
    alias(sphereonplug.plugins.org.jetbrains.kotlin.plugin.serialization)
    alias(sphereonplug.plugins.dev.zacsweers.metro)
    alias(sphereonplug.plugins.com.sphereon.gradle.plugin.project.publication)
    id("maven-publish")
}

metro {
}

kotlin {
    jvm()

    sourceSets {
        val commonMain by getting {
            dependencies {
                // IDK status-list commands + models (the ServiceCommand interface this REST surface delegates to).
                api(if (rootProject.findProperty("idk.consumeProtocolsAsArtifacts") == "true") "com.sphereon.idk:lib-statuslist-public:$version" else project(":lib-statuslist-public"))
                // IDK core API (HTTP adapter types + response helpers).
                api(if (rootProject.findProperty("idk.consumeCoreAsArtifacts") == "true") "com.sphereon.idk:lib-core-api-public:$version" else project(":lib-core-api-public"))

                implementation(sphereonlib.org.jetbrains.kotlinx.serialization.json)
                implementation(sphereonlib.org.jetbrains.kotlinx.coroutines.core)

                implementation(libs.bundles.app.platform.di)
                api(sphereonlib.software.amazon.app.platform.metro.public)
                api(sphereonlib.software.amazon.app.platform.metro.impl)
            }
        }
        val commonTest by getting {
            dependencies {
                implementation(project(":lib-statuslist-impl"))
                implementation(kotlin("test"))
                implementation(sphereonlib.org.jetbrains.kotlinx.coroutines.test)
                implementation(sphereonlib.org.jetbrains.kotlinx.serialization.json)
            }
        }
    }
}
