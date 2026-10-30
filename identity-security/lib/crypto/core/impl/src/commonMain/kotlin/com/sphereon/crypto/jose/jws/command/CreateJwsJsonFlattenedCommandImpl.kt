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
import com.sphereon.crypto.jose.jws.JwsJsonFlattened
import com.sphereon.crypto.jose.jws.command.CreateJwsJsonArgs
import com.sphereon.crypto.jose.jws.command.CreateJwsJsonFlattenedCommand
import com.sphereon.crypto.jose.jws.command.CreateJwsJsonGeneralCommand
import com.sphereon.di.session.SessionContext
import com.sphereon.di.session.SessionScope
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import kotlin.experimental.ExperimentalObjCName
import kotlin.native.ObjCName

import dev.zacsweers.metro.ExposeImplBinding
/**
 * Command implementation for creating flattened JSON JWS
 */
@Inject
@SingleIn(SessionScope::class)
@OptIn(ExperimentalObjCName::class)
@ObjCName("CreateJwsJsonFlattenedCommandImpl", exact = true)
@ExposeImplBinding
class CreateJwsJsonFlattenedCommandImpl(
    execution: SessionExecution,
    private val createJwsJsonGeneralCommand: CreateJwsJsonGeneralCommand,
) : TypedServiceCommandAdapter<CreateJwsJsonArgs, JwsJsonFlattened, IdkError>(
        commandId = CreateJwsJsonFlattenedCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<CreateJwsJsonArgs>(),
        outputTypeToken = typeToken<JwsJsonFlattened>(),
    ),
    CreateJwsJsonFlattenedCommand {
    override val commandId: String get() = CreateJwsJsonFlattenedCommand.COMMAND_ID

    override suspend fun doExecute(
        args: CreateJwsJsonArgs,
        applyDuring: (CreateJwsJsonArgs) -> CreateJwsJsonArgs,
    ): IdkResult<JwsJsonFlattened, IdkError> {
        val appliedArgs = applyDuring(args)

        // Create general JWS first
        val generalResult = createJwsJsonGeneralCommand.execute(appliedArgs)
        if (generalResult.isErr) {
            log.error("JWS signing failed command=$commandId stage=general-signing")
            return IdkResult.err(generalResult.error)
        }

        val general = generalResult.value

        // Verify only one signature
        if (general.signatures.size != 1) {
            log.error("JWS signing failed command=$commandId stage=signature-count count=${general.signatures.size}")
            return IdkResult.err(
                IdkError.fromString("Flattened JWS must have exactly one signature, found ${general.signatures.size}"),
            )
        }

        // Convert to flattened format
        val signature = general.signatures.first()
        val flattened =
            JwsJsonFlattened(
                payload = general.payload,
                protected = signature.protected,
                header = signature.header,
                signature = signature.signature,
            )

        return flattened.asOkResult()
    }
}
