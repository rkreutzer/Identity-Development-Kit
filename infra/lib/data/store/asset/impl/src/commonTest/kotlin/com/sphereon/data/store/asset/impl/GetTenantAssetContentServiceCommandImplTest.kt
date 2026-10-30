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

package com.sphereon.data.store.asset.impl

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.error.ErrorCategory
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.service.ActionType
import com.sphereon.data.store.asset.TenantAssetService
import com.sphereon.data.store.asset.command.GetTenantAssetContentArgs
import com.sphereon.data.store.asset.command.GetTenantAssetContentServiceCommand
import com.sphereon.data.store.asset.impl.command.GetTenantAssetContentServiceCommandImpl
import com.sphereon.data.store.asset.model.AssetInfo
import com.sphereon.data.store.asset.model.AssetNamespace
import com.sphereon.data.store.asset.model.AssetReference
import com.sphereon.data.store.asset.model.ResolvedAsset
import com.sphereon.data.store.asset.model.UploadAssetInput
import com.sphereon.di.context.IdentityConstants
import com.sphereon.di.context.PrincipalType
import com.sphereon.di.context.SecuredTenantContextDetails
import com.sphereon.di.context.TenantContextData
import com.sphereon.di.context.UserContext
import com.sphereon.di.session.SessionContext
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertSame
import kotlin.test.assertTrue

class GetTenantAssetContentServiceCommandImplTest {
    private val sha256OfAbc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    private val request = GetTenantAssetContentArgs(AssetNamespace.BRAND, sha256OfAbc)
    private val asset =
        ResolvedAsset(
            byteArrayOf(1),
            "image/png",
            AssetInfo("/public/assets/tenant-a/brand/$sha256OfAbc.png", "image/png", sha256OfAbc),
        )
    private var failure: IdkError? = null
    private val reads = mutableListOf<Triple<String, AssetNamespace, String>>()
    private val owner =
        object : TenantAssetService {
            override suspend fun getAssetContent(
                tenantId: String,
                namespace: AssetNamespace,
                hash: String,
            ): IdkResult<ResolvedAsset, IdkError> {
                reads.add(Triple(tenantId, namespace, hash))
                return failure?.let { Err(it) } ?: Ok(asset)
            }

            override suspend fun uploadAsset(
                tenantId: String,
                input: UploadAssetInput,
            ): IdkResult<AssetReference, IdkError> = error("Unexpected write")

            override suspend fun listAssets(
                tenantId: String,
                namespace: AssetNamespace,
                contentType: String?,
            ): IdkResult<List<AssetInfo>, IdkError> = error("Unexpected listing")

            override suspend fun getAsset(
                tenantId: String,
                namespace: AssetNamespace,
                hash: String,
            ): IdkResult<AssetInfo, IdkError> = error("Unexpected read")

            override suspend fun deleteAsset(
                tenantId: String,
                namespace: AssetNamespace,
                hash: String,
            ): IdkResult<Unit, IdkError> = error("Unexpected delete")
        }

    @Test
    fun shouldUseSessionTenantAndPassAllArgumentsToCanonicalOwner() =
        runTest {
            val command = GetTenantAssetContentServiceCommandImpl(execution(), owner)
            for (namespace in AssetNamespace.entries) {
                val result = command.execute(GetTenantAssetContentArgs(namespace, sha256OfAbc))
                assertSame(asset, result.getOrElse { error(it.toString()) })
            }
            assertEquals(AssetNamespace.entries.map { Triple("tenant-a", it, sha256OfAbc) }, reads)
        }

    @Test
    fun shouldForwardTheAssetLibraryErrorUnchanged() =
        runTest {
            val missing = IdkError.NOT_FOUND_ERROR(message = "Missing asset")
            failure = missing
            val command = GetTenantAssetContentServiceCommandImpl(execution(), owner)
            assertSame(missing, command.execute(request).errorOrNull())
        }

    @Test
    fun shouldAcceptServiceAndWorkloadPrincipals() =
        runTest {
            for (type in listOf(PrincipalType.SERVICE, PrincipalType.WORKLOAD)) {
                val command = GetTenantAssetContentServiceCommandImpl(execution(type = type), owner)
                assertSame(asset, command.execute(request).getOrElse { error(it.toString()) })
            }
            assertEquals(2, reads.size)
        }

    @Test
    fun shouldRefuseAnUnresolvedTenantAsUnauthorizedBeforeReading() =
        runTest {
            val contexts =
                listOf(
                    execution(tenant = ""),
                    execution(tenant = IdentityConstants.ANONYMOUS_TENANT_ID),
                )
            for (context in contexts) {
                val error = checkNotNull(GetTenantAssetContentServiceCommandImpl(context, owner).execute(request).errorOrNull())
                assertEquals(ErrorCategory.UNAUTHORIZED, error.category)
                assertEquals("UNAUTHORIZED", error.code)
            }
            assertTrue(reads.isEmpty())
        }

    @Test
    fun shouldReadForAnAnonymousPrincipalOfAResolvedTenant() =
        runTest {
            val contexts =
                listOf(
                    execution(actor = null),
                    execution(actor = ""),
                    execution(actor = IdentityConstants.ANONYMOUS_PRINCIPAL_ID),
                    execution(type = PrincipalType.ANONYMOUS),
                    execution(anonymous = true),
                )
            for (context in contexts) {
                val command = GetTenantAssetContentServiceCommandImpl(context, owner)
                assertSame(asset, command.execute(request).getOrElse { error(it.toString()) })
            }
            assertEquals(contexts.size, reads.size)
            assertTrue(reads.all { it.first == "tenant-a" })
        }

    @Test
    fun shouldRefuseMalformedOrNoncanonicalHashAsValidationBeforeReading() =
        runTest {
            val command = GetTenantAssetContentServiceCommandImpl(execution(), owner)
            val invalid =
                listOf(
                    "",
                    sha256OfAbc.dropLast(1),
                    "${sha256OfAbc}0",
                    sha256OfAbc.uppercase(),
                    "g".repeat(64),
                    "$sha256OfAbc\n",
                    "a".repeat(32),
                    "a".repeat(40),
                    "a".repeat(97),
                )
            for (hash in invalid) {
                val error = checkNotNull(command.execute(GetTenantAssetContentArgs(AssetNamespace.BRAND, hash)).errorOrNull())
                assertEquals(ErrorCategory.VALIDATION, error.category)
                assertEquals("ASSET_VALIDATION_ERROR", error.code)
            }
            assertTrue(reads.isEmpty())
        }

    @Test
    fun shouldLeaveTheExistenceOfAnAssetWithAnotherRegisteredDigestLengthToTheLibrary() =
        runTest {
            val command = GetTenantAssetContentServiceCommandImpl(execution(), owner)
            val digests = listOf("a".repeat(96), "b".repeat(128))
            for (hash in digests) {
                val result = command.execute(GetTenantAssetContentArgs(AssetNamespace.BRAND, hash))
                assertSame(asset, result.getOrElse { error(it.toString()) })
            }
            assertEquals(digests, reads.map { it.third })
        }

    @Test
    fun shouldBeAReadCommandUnderItsCommandId() {
        val command = GetTenantAssetContentServiceCommandImpl(execution(), owner)
        assertEquals("assets.content.get", GetTenantAssetContentServiceCommand.COMMAND_ID)
        assertEquals(GetTenantAssetContentServiceCommand.COMMAND_ID, command.commandId)
        assertEquals(ActionType.READ, command.actionType)
    }

    private fun execution(
        tenant: String = "tenant-a",
        actor: String? = "publisher",
        type: PrincipalType = PrincipalType.USER,
        anonymous: Boolean = false,
    ): TestSessionExecution {
        val tenantContext =
            object : TenantContextData {
                override val tenantId = tenant
            }
        val user =
            object : UserContext {
                override val id = "asset-reader"
                override val secureDetails: SecuredTenantContextDetails? = null
                override val tenant = tenantContext
                override val principal: Any? = actor
                override val principalType = type
            }
        return TestSessionExecution(
            object : SessionContext {
                override val sessionId = "asset-read-session"
                override val context = user

                override fun isAnonymous() = anonymous
            },
        )
    }
}
