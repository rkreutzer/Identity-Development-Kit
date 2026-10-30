/*
 * (c) 2026 Sphereon International B.V.
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package com.sphereon.oidf.conformance

import com.github.dockerjava.api.command.CreateNetworkCmd
import org.testcontainers.containers.Network
import java.lang.reflect.Proxy
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class OidfSuiteNetworkTest {
    @Test
    fun advertisedHostPreservesContainerDefaultAndAllowsTheHostResolvableSuiteName() {
        assertEquals("host.testcontainers.internal", oidfSuiteAdvertisedHost(null))
        assertEquals("localhost.emobix.co.uk", oidfSuiteAdvertisedHost("localhost.emobix.co.uk"))
        assertFailsWith<IllegalArgumentException> { oidfSuiteAdvertisedHost("uncertified.example") }
    }

    @Test
    fun defaultNetworkUsesDockerAddressAllocation() {
        val network = oidfSuiteNetwork(null) as Network.NetworkImpl
        assertTrue(network.createNetworkCmdModifiers.isEmpty())
    }

    @Test
    fun explicitSubnetIsAppliedToTheDockerNetworkCommand() {
        var ipam: com.github.dockerjava.api.model.Network.Ipam? = null
        val command =
            Proxy.newProxyInstance(CreateNetworkCmd::class.java.classLoader, arrayOf(CreateNetworkCmd::class.java)) { proxy, method, args ->
                if (method.name == "withIpam") ipam = args!![0] as com.github.dockerjava.api.model.Network.Ipam
                proxy
            } as CreateNetworkCmd
        val network = oidfSuiteNetwork("10.254.100.0/24") as Network.NetworkImpl
        network.createNetworkCmdModifiers.forEach { it.accept(command) }
        assertEquals("10.254.100.0/24", ipam!!.config.single().subnet)
    }
}
