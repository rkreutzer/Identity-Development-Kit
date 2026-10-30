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

package com.sphereon.crypto.jose.jws

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.error.IdkError
import com.sphereon.crypto.jose.jws.command.CreateJwsArgs
import com.sphereon.crypto.jose.jws.command.CreateJwsCompactCommand
import com.sphereon.crypto.jose.jws.command.CreateJwsJsonArgs
import com.sphereon.crypto.jose.jws.command.CreateJwsJsonFlattenedCommand
import com.sphereon.crypto.jose.jws.command.CreateJwsJsonGeneralCommand
import com.sphereon.crypto.jose.jws.command.PrepareJwsCommand
import com.sphereon.crypto.jose.jws.command.VerifyJwsArgs
import com.sphereon.crypto.jose.jws.command.VerifyJwsCommand
import com.sphereon.di.session.SessionScope
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding
import kotlin.experimental.ExperimentalObjCName
import kotlin.native.ObjCName

/**
 * Implementation of JwtService that delegates to command implementations
 */
@dev.zacsweers.metro.Inject
@SingleIn(SessionScope::class)
@ContributesBinding(SessionScope::class, binding = binding<JwtService>())
@OptIn(ExperimentalObjCName::class)
@ObjCName("JwtServiceImpl", exact = true)
class JwtServiceImpl(
    private val prepareJwsCommand: Lazy<PrepareJwsCommand>,
    private val createJwsCompactCommand: Lazy<CreateJwsCompactCommand>,
    private val createJwsJsonFlattenedCommand: Lazy<CreateJwsJsonFlattenedCommand>,
    private val createJwsJsonGeneralCommand: Lazy<CreateJwsJsonGeneralCommand>,
    private val verifyJwsCommand: Lazy<VerifyJwsCommand>,
) : JwtService {
    @dev.zacsweers.metro.ContributesTo(scope = SessionScope::class)
    interface Graph {
        val jwtService: JwtService
    }

    /**
     * Implementation of Commands that exposes the injected command instances
     */
    inner class CommandsImpl : JwtService.Commands {
        override val prepareJws: PrepareJwsCommand get() = this@JwtServiceImpl.prepareJwsCommand.value
        override val createJwsCompact: CreateJwsCompactCommand get() = this@JwtServiceImpl.createJwsCompactCommand.value
        override val createJwsJsonFlattened: CreateJwsJsonFlattenedCommand get() = this@JwtServiceImpl.createJwsJsonFlattenedCommand.value
        override val createJwsJsonGeneral: CreateJwsJsonGeneralCommand get() = this@JwtServiceImpl.createJwsJsonGeneralCommand.value
        override val verifyJws: VerifyJwsCommand get() = this@JwtServiceImpl.verifyJwsCommand.value
    }

    override val commands: JwtService.Commands = CommandsImpl()

    override fun assembleJwsGeneral(
        prepared: PreparedJwsObject,
        signatureBytes: ByteArray,
    ): JwsJsonGeneral = prepared.assembleGeneral(signatureBytes)

    override fun assembleJwsFlattened(
        prepared: PreparedJwsObject,
        signatureBytes: ByteArray,
    ): JwsJsonFlattened = prepared.assembleFlattened(signatureBytes)

    override fun assembleJwsCompact(
        prepared: PreparedJwsObject,
        signatureBytes: ByteArray,
    ): JwtCompactResult = prepared.assembleCompact(signatureBytes)

    // Delegate service methods to commands
    override suspend fun prepareJws(args: CreateJwsJsonArgs): IdkResult<PreparedJwsObject, IdkError> = prepareJwsCommand.value.execute(args)

    override suspend fun createJwsCompact(args: CreateJwsArgs): IdkResult<JwtCompactResult, IdkError> = createJwsCompactCommand.value.execute(args)

    override suspend fun createJwsJsonFlattened(args: CreateJwsJsonArgs): IdkResult<JwsJsonFlattened, IdkError> = createJwsJsonFlattenedCommand.value.execute(args)

    override suspend fun createJwsJsonGeneral(args: CreateJwsJsonArgs): IdkResult<JwsJsonGeneral, IdkError> = createJwsJsonGeneralCommand.value.execute(args)

    override suspend fun verifyJws(args: VerifyJwsArgs): IdkResult<JwsValidationResult, IdkError> = verifyJwsCommand.value.execute(args)
}
