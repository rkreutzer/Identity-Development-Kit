package com.sphereon.openid.oid4vci.issuer.ktor

import com.sphereon.core.api.conf.DefaultAppMapPropertySource
import com.sphereon.core.api.error.ErrorCategory
import com.sphereon.core.api.service.SessionScopedCommandRegistry
import com.sphereon.core.defaults.context.DefaultPrincipalInputString
import com.sphereon.core.defaults.context.DefaultTenantInputString
import com.sphereon.data.store.asset.command.GetTenantAssetContentArgs
import com.sphereon.data.store.asset.command.GetTenantAssetContentServiceCommand
import com.sphereon.data.store.asset.model.AssetNamespace
import com.sphereon.data.store.blob.BlobInfo
import com.sphereon.data.store.blob.impl.DefaultBlobService
import com.sphereon.di.app.AppGraph
import com.sphereon.di.context.PrincipalType
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/** The standalone issuer must serve real tenant asset bytes through its own assembled graph. */
class IssuerTenantAssetContentTest {
    private val hash = "0f4636c78f65d3639ece5a064b5ae753e3408614a14fb18ab4d7540d2c248543"
    private val bytes = byteArrayOf(0x89.toByte(), 0x50, 0x4e, 0x47)

    @Test
    fun issuerReadsStoredAssetBytesOnlyWithinTheResolvedTenant() = withIssuer { graph ->
        val owner = graph.userContextManager.createOrGetFromInputs(
            DefaultTenantInputString("asset-owner"), DefaultPrincipalInputString("asset-test"),
        ).sessionContextManager
        val other = graph.userContextManager.createOrGetFromInputs(
            DefaultTenantInputString("other-tenant"), DefaultPrincipalInputString("asset-test"),
        ).sessionContextManager
        val ownerSession = owner.createOrGetFromId("issuer-asset-owner", principalType = PrincipalType.SERVICE)
        val otherSession = other.createOrGetFromId("issuer-asset-other", principalType = PrincipalType.SERVICE)
        try {
            val blobs = (ownerSession.graph as DefaultBlobService.Graph).blobService
            val stored = blobs.storeBlob(
                BlobInfo(tenantId = "asset-owner", path = "assets/asset-owner/brand/by-hash/$hash", contentType = "image/png"),
                bytes,
            )
            assertTrue(stored.isOk, "The issuer's actual memory blob backend must store the fixture")
            val command = assertIs<GetTenantAssetContentServiceCommand>(
                (ownerSession.graph as SessionScopedCommandRegistry.Graph).sessionScopedCommandRegistry
                    .get(GetTenantAssetContentServiceCommand.COMMAND_ID),
            )
            val read = command.execute(GetTenantAssetContentArgs(AssetNamespace.BRAND, hash))
            assertTrue(read.isOk, "The assembled issuer must read the stored asset")
            assertContentEquals(bytes, read.value.data)
            assertEquals("image/png", read.value.contentType)
            assertEquals("/public/assets/asset-owner/brand/$hash.png", read.value.info.uri)

            val otherCommand = assertIs<GetTenantAssetContentServiceCommand>(
                (otherSession.graph as SessionScopedCommandRegistry.Graph).sessionScopedCommandRegistry
                    .get(GetTenantAssetContentServiceCommand.COMMAND_ID),
            )
            val crossTenant = otherCommand.execute(GetTenantAssetContentArgs(AssetNamespace.BRAND, hash))
            assertTrue(crossTenant.isErr)
            assertEquals(ErrorCategory.NOT_FOUND, crossTenant.error.category)
        } finally {
            other.destroyById("issuer-asset-other")
            owner.destroyById("issuer-asset-owner")
        }
    }

    @Test
    fun issuerRefusesAssetContentWhenTheTenantIsUnresolved() = withIssuer { graph ->
        val sessions = graph.userContextManager.getAnonymous().sessionContextManager
        val session = sessions.createOrGetFromId("issuer-asset-anonymous", principalType = PrincipalType.ANONYMOUS)
        try {
            val command = assertIs<GetTenantAssetContentServiceCommand>(
                (session.graph as SessionScopedCommandRegistry.Graph).sessionScopedCommandRegistry
                    .get(GetTenantAssetContentServiceCommand.COMMAND_ID),
            )
            val read = command.execute(GetTenantAssetContentArgs(AssetNamespace.BRAND, hash))
            assertTrue(read.isErr)
            assertEquals(ErrorCategory.UNAUTHORIZED, read.error.category)
        } finally {
            sessions.destroyById("issuer-asset-anonymous")
        }
    }

    private fun withIssuer(body: suspend (AppGraph) -> Unit) = runBlocking {
        DefaultAppMapPropertySource.getSource().clear()
        DefaultAppMapPropertySource.addProperties(mapOf(
            "kms.providers.software.type" to "software",
            "kms.providers.software.id" to "software",
            "kms.providers.software.keystore.type" to "memory",
            "kms.providers.software.keystore.id" to "issuer-asset-test",
            "kms.providers.software.keystore.keyVisibility" to "private",
            "blob.stores.memory.type" to "memory",
            "blob.stores.memory.id" to "memory",
            "blob.stores.memory.scopeBinding" to "TENANT",
            "kv.stores.blob.metadata.type" to "memory",
            "kv.stores.blob.metadata.id" to "blob.metadata",
            "kv.stores.blob.metadata.scopeBinding" to "TENANT",
        ))
        val graph = createOid4vciIssuerAppGraph(application = Unit, appId = "issuer-asset-test", profile = "test", version = "test")
        try {
            body(graph)
        } finally {
            graph.destroy()
            DefaultAppMapPropertySource.getSource().clear()
        }
    }
}
