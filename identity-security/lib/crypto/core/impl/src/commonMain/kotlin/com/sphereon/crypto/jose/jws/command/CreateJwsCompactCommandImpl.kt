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

package com.sphereon.crypto.jose.jws.command

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.asOkResult
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.service.TypedServiceCommandAdapter
import com.sphereon.crypto.jose.jws.JwtCompactResult
import com.sphereon.crypto.jose.jws.command.CreateJwsArgs
import com.sphereon.crypto.jose.jws.command.CreateJwsCompactCommand
import com.sphereon.crypto.jose.jws.command.CreateJwsJsonArgs
import com.sphereon.crypto.jose.jws.command.CreateJwsJsonFlattenedCommand
import com.sphereon.di.session.SessionContext
import com.sphereon.di.session.SessionScope
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import kotlin.experimental.ExperimentalObjCName
import kotlin.native.ObjCName

import dev.zacsweers.metro.ExposeImplBinding
/**
 * Command implementation for creating compact JWS (header.payload.signature)
 */
@Inject
@SingleIn(SessionScope::class)
@OptIn(ExperimentalObjCName::class)
@ObjCName("CreateJwsCompactCommandImpl", exact = true)
@ExposeImplBinding
class CreateJwsCompactCommandImpl(
    execution: SessionExecution,
    private val createJwsJsonFlattenedCommand: CreateJwsJsonFlattenedCommand,
) : TypedServiceCommandAdapter<CreateJwsArgs, JwtCompactResult, IdkError>(
        commandId = CreateJwsCompactCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<CreateJwsArgs>(),
        outputTypeToken = typeToken<JwtCompactResult>(),
    ),
    CreateJwsCompactCommand {
    override val commandId: String get() = CreateJwsCompactCommand.COMMAND_ID

    override suspend fun doExecute(
        args: CreateJwsArgs,
        applyDuring: (CreateJwsArgs) -> CreateJwsArgs,
    ): IdkResult<JwtCompactResult, IdkError> {
        val appliedArgs = applyDuring(args)

        // Convert CreateJwsArgs to CreateJwsJsonArgs
        val jsonArgs =
            CreateJwsJsonArgs(
                issuer = appliedArgs.issuer,
                payload = appliedArgs.payload,
                mode = appliedArgs.mode,
                opts = appliedArgs.opts,
            )

        // Create flattened JWS first
        val flattenedResult = createJwsJsonFlattenedCommand.execute(jsonArgs)
        if (flattenedResult.isErr) {
            log.error("JWS signing failed command=$commandId stage=flattened-signing idk_code=${flattenedResult.error.code}")
            return IdkResult.err(flattenedResult.error)
        }

        val flattened = flattenedResult.value

        // Convert to compact format: header.payload.signature
        val compact = "${flattened.protected}.${flattened.payload}.${flattened.signature}"

        val result = JwtCompactResult(jwt = compact)
        return result.asOkResult()
    }
}
