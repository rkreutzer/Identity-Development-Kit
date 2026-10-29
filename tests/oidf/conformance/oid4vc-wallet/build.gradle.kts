/*
 * (c) 2026 Sphereon International B.V.
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Live OIDF wallet adapter. Keeping this outside wallet-runner's own test
 * source set prevents unrelated product tests from becoming prerequisites for
 * the independently sharded conformance lane.
 */

import java.nio.file.Files

plugins {
    alias(sphereonplug.plugins.org.jetbrains.kotlin.jvm)
    alias(sphereonplug.plugins.org.jetbrains.kotlin.plugin.serialization)
}

kotlin {
    jvmToolchain(17)
}

// The root settings loads the canonical published platform version before build scripts.
val idkArtifactVersion = rootProject.extra["platformVersion"].toString()

dependencies {
    implementation(projects.testsOidfConformanceOid4vc)
    // Product publications are owned by the standalone wallet repository; SDK libraries
    // below are owned by the IDK wallet-lib pack. Both retain their published IDK coordinates.
    implementation("com.sphereon.idk:wallet-runner:$idkArtifactVersion")
    implementation("com.sphereon.idk:wallet-app-public:$idkArtifactVersion")
    implementation("com.sphereon.idk:lib-wallet-public:$idkArtifactVersion")
    implementation("com.sphereon.idk:lib-wallet-interaction-public:$idkArtifactVersion")
    implementation("com.sphereon.idk:lib-wallet-interaction-protocol-oid4vci:$idkArtifactVersion")
    implementation("com.sphereon.idk:lib-wallet-interaction-protocol-oid4vp:$idkArtifactVersion")
    implementation(sphereonlib.org.jetbrains.kotlinx.coroutines.core)
    implementation(sphereonlib.org.jetbrains.kotlinx.serialization.json)

    testImplementation("com.sphereon.idk:wallet-app-impl:$idkArtifactVersion")
    testImplementation(kotlin("test"))
    testImplementation(sphereonlib.org.jetbrains.kotlinx.coroutines.test)
    testImplementation(sphereonlib.org.junit.jupiter.junit.jupiter.engine)
    testImplementation(sphereonlib.org.bouncycastle.bcprov.jdk18on)
    testImplementation(sphereonlib.org.bouncycastle.bcpkix.jdk18on)
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
    // Relative runtime stores must be isolated per execution, outside the source tree.
    val runtimeRoot =
        layout.buildDirectory
            .dir("oidf-runtime")
            .get()
            .asFile
    val sutWorkspace = projectDir.absolutePath
    doFirst {
        runtimeRoot.mkdirs()
        workingDir(Files.createTempDirectory(runtimeRoot.toPath(), "run-").toFile())
    }
    systemProperty("oidf.sut.workspace", sutWorkspace)
    val evidenceDirectory =
        System.getProperty("oidf.evidence.dir")
            ?: providers.gradleProperty("oidf.evidence.dir").orNull
            ?: layout.buildDirectory
                .dir("oidf-evidence")
                .get()
                .asFile.absolutePath
    systemProperty("oidf.evidence.dir", evidenceDirectory)
    listOf(
        "oidf.suite.baseUrl",
        "oidf.suite.apiBaseUrl",
        "oidf.suite.protocolBaseUrl",
        "oidf.suite.caCert",
        "oidf.suite.dir",
        "oidf.suite.mode",
        "oidf.plan",
        "oidf.scenario",
        "oidf.module",
        "oidf.sut.workspace",
        "javax.net.ssl.trustStore",
        "javax.net.ssl.trustStorePassword",
        "javax.net.ssl.trustStoreType",
    ).forEach { key ->
        val value = System.getProperty(key) ?: providers.gradleProperty(key).orNull
        if (!value.isNullOrBlank()) systemProperty(key, value)
    }
}
