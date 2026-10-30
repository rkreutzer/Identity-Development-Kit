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

package com.sphereon.openid.oid4vp.verifier.impl.testutil

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.binary.TypeToken
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.error.IdkError
import com.sphereon.jsonld.loader.BuiltInContextLinkedDataDocumentLoader
import com.sphereon.jsonld.loader.DefaultBuiltInContextRegistry
import com.sphereon.jsonld.loader.LinkedDataDocumentLoader
import com.sphereon.openid.oid4vp.verifier.CredentialTypeMatcher
import com.sphereon.openid.oid4vp.verifier.impl.CredentialTypeMatcherImpl
import com.sphereon.sdjwt.vc.ResolveTypeMetadataArgs
import com.sphereon.sdjwt.vc.SdJwtVcTypeMatcherImpl
import com.sphereon.sdjwt.vc.StaticTypeMetadataResolver
import com.sphereon.sdjwt.vc.TypeMetadataResolutionResult
import com.sphereon.sdjwt.vc.TypeMetadataResolver
import com.sphereon.sdjwt.vc.command.ResolveTypeMetadataCommand

/** Resolves type metadata from a fixed resolver and counts the lookups, so a test needs no network. */
internal class CountingTypeMetadataCommand(
    private val resolver: TypeMetadataResolver = StaticTypeMetadataResolver(emptyMap()),
) : ResolveTypeMetadataCommand {
    val resolvedVcts = mutableListOf<String>()

    override val commandId: String = ResolveTypeMetadataCommand.COMMAND_ID
    override val inputTypeToken: TypeToken<ResolveTypeMetadataArgs> = typeToken<ResolveTypeMetadataArgs>()
    override val outputTypeToken: TypeToken<TypeMetadataResolutionResult> = typeToken<TypeMetadataResolutionResult>()
    override val isEnabled: Boolean = true

    override suspend fun supports(args: Any): Boolean = args is ResolveTypeMetadataArgs

    override suspend fun execute(args: ResolveTypeMetadataArgs): IdkResult<TypeMetadataResolutionResult, IdkError> {
        resolvedVcts += args.vct
        return Ok(resolver.resolve(args.vct))
    }
}

/** The real matcher over a counting static metadata command and the bundled JSON-LD contexts. */
internal fun testCredentialTypeMatcher(
    metadata: CountingTypeMetadataCommand = CountingTypeMetadataCommand(),
    documentLoader: LinkedDataDocumentLoader = BuiltInContextLinkedDataDocumentLoader(DefaultBuiltInContextRegistry()),
): CredentialTypeMatcher = CredentialTypeMatcherImpl(SdJwtVcTypeMatcherImpl(metadata), documentLoader)
