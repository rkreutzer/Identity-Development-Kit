/* © 2026 Sphereon International B.V. */
package com.sphereon.oauth2.server.authorization.impl.command.orchestration

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.error.IdkError
import com.sphereon.crypto.core.jose.JwaAlgorithm
import com.sphereon.crypto.core.jose.JwaKeyType
import com.sphereon.crypto.core.jose.Jwk
import com.sphereon.oauth2.common.command.VerifyDpopProofCommand
import com.sphereon.oauth2.common.config.OAuth2ServerInstanceConfig
import com.sphereon.oauth2.common.config.OAuth2ServersConfig
import com.sphereon.oauth2.common.model.*
import com.sphereon.oauth2.server.authorization.command.*
import com.sphereon.oauth2.server.authorization.command.token.*
import com.sphereon.oauth2.server.authorization.dpop.DpopProofJtiCache
import com.sphereon.oauth2.server.authorization.dpop.DpopNonceManager
import com.sphereon.oauth2.server.authorization.impl.command.token.HandleTokenRequestCommandImpl
import com.sphereon.oauth2.server.authorization.impl.testutil.OAuth2ServerTestContext
import com.sphereon.oauth2.server.authorization.impl.testutil.TestOAuth2ServersConfigProvider
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.assertFailsWith
import kotlinx.coroutines.CancellationException
import kotlin.time.Clock
import kotlin.time.Instant

/** Consumer-boundary unit tests; proof verification is stubbed, not cryptographic acceptance. */
class DpopAtomicReplayBoundaryTest {
    private val ctx = OAuth2ServerTestContext("atomic-dpop-replay", this)

    @Test fun rejectedAtomicReplayReservationStopsGrantBeforeTokenIssuance() = runTest {
        checkAtomicBoundary(throwOnReservation = false)
    }
    @Test fun atomicReplayStorageFailureFailsClosedBeforeTokenIssuance() = runTest {
        checkAtomicBoundary(throwOnReservation = true)
    }
    @Test fun cancelledAtomicReservationCannotReachGrantEffects() = runTest {
        assertFailsWith<CancellationException> { checkAtomicBoundary(cancelReservation = true) }
    }
    @Test fun acceptedAtomicReservationUsesNoLegacyPeekOrMark() = runTest {
        checkAtomicBoundary(acceptReservation = true)
    }
    @Test fun unicodeProofIdentifierUsesUtf8ByteLengthFraming() = runTest {
        checkAtomicBoundary(proofId = "proof-🌐:é")
    }
    private suspend fun checkAtomicBoundary(throwOnReservation: Boolean = false,
        acceptReservation: Boolean = false, cancelReservation: Boolean = false, proofId: String = "proof-id") {
        var reservations = 0; var issued = 0; var legacyReads = 0; var legacyWrites = 0
        var reservedIdentifier: String? = null
        val cache = object : DpopProofJtiCache {
            override suspend fun hasBeenUsed(jti: String): Boolean { legacyReads++; return false }
            override suspend fun markAsUsed(jti: String, expiresAt: Instant) { legacyWrites++ }
            override suspend fun clear() = Unit
            override suspend fun recordIfNew(jti: String, expiresAt: Instant): Boolean {
                reservations++
                reservedIdentifier = jti
                if (cancelReservation) throw CancellationException("fixture replay reservation cancelled")
                if (throwOnReservation) error("replay store unavailable")
                return acceptReservation
            }
        }
        val parse = object : ParseTokenRequestCommand {
            override val inputTypeToken = typeToken<ParseTokenRequestArgs>()
            override val outputTypeToken = typeToken<TokenRequestData>()
            override val isEnabled = true
            override suspend fun execute(args: ParseTokenRequestArgs) = Ok(TokenRequestData(
                grantType = GrantType.CLIENT_CREDENTIALS, clientId = "client",
                clientAuthentication = ClientAuthenticationConfig.Anonymous,
                grantParameters = GrantParameters.ClientCredentials(scope = "read"),
                httpUrl = "https://as.example/token", dpopProof = "verified-proof",
            ))
        }
        val client = object : VerifyClientAuthenticationCommand {
            override val inputTypeToken = typeToken<VerifyClientAuthenticationArgs>()
            override val outputTypeToken = typeToken<VerifiedClientAuthentication>()
            override val isEnabled = true
            override suspend fun execute(args: VerifyClientAuthenticationArgs) = Ok(VerifiedClientAuthentication(clientId = "client", method = ClientAuthenticationMethod.NONE))
        }
        val proof = object : VerifyDpopProofCommand {
            override val inputTypeToken = typeToken<VerifyDpopProofOptions>()
            override val outputTypeToken = typeToken<VerifyDpopProofResult>()
            override val isEnabled = true
            override suspend fun execute(args: VerifyDpopProofOptions) = Ok(VerifyDpopProofResult(
                header = DpopJwtHeader(alg = "ES256", jwk = Jwk(kty = JwaKeyType.EC, alg = JwaAlgorithm.ES256)),
                payload = DpopJwtPayload(jti = proofId, htm = "POST", htu = args.httpUrl, iat = Clock.System.now().epochSeconds),
                jwkThumbprint = "verified-public-key-thumbprint",
            ))
        }
        val handler = object : GrantHandler {
            override val grantType = GrantHandlerKeys.CLIENT_CREDENTIALS
            override fun supports(params: GrantParameters) = params is GrantParameters.ClientCredentials
            override suspend fun handle(params: GrantParameters, context: GrantContext): IdkResult<TokenResponse, IdkError> {
                issued++; return Ok(TokenResponse(accessToken = "must-not-issue", tokenType = "DPoP"))
            }
        }
        val command = HandleTokenRequestCommandImpl(
            execution = ctx.execution, parseTokenRequestCommand = parse, verifyClientAuthenticationCommand = lazyOf(client),
            serversConfigProvider = TestOAuth2ServersConfigProvider(OAuth2ServersConfig(servers = mapOf("default" to OAuth2ServerInstanceConfig(issuer = "https://as.example")))),
            verifyDpopProofCommand = lazyOf(proof), dpopProofJtiCache = lazyOf(cache),
            dpopNonceManager = lazy<DpopNonceManager> { error("Nonce policy is disabled in this boundary vector") },
            grantHandlers = mapOf(handler.grantType to lazyOf(handler)),
        )
        val result = try {
            command.execute(HandleTokenRequestArgs(requestBody = mapOf("grant_type" to listOf("client_credentials")), requestHeaders = emptyMap(), httpUrl = "https://as.example/token"))
        } catch (cancelled: CancellationException) {
            assertEquals(1, reservations); assertEquals(0, legacyReads); assertEquals(0, legacyWrites); assertEquals(0, issued)
            throw cancelled
        }
        if (acceptReservation) assertTrue(result.isOk) else {
            assertTrue(result.isErr)
            assertEquals("invalid_dpop_proof", result.error.code)
        }
        assertEquals(1, reservations); assertEquals(0, legacyReads); assertEquals(0, legacyWrites); assertEquals(if (acceptReservation) 1 else 0, issued)
        val thumbprint = "verified-public-key-thumbprint"
        assertEquals("${thumbprint.encodeToByteArray().size}:$thumbprint${proofId.encodeToByteArray().size}:$proofId", reservedIdentifier)
    }
}
