package com.sphereon.crypto.kms.provider.aws

import aws.sdk.kotlin.services.kms.KmsClient
import aws.sdk.kotlin.services.kms.model.*
import com.sphereon.crypto.core.KeyInfo
import com.sphereon.crypto.core.KeyType
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.crypto.core.jose.Jwk
import com.sphereon.crypto.core.kms.*
import com.sphereon.crypto.core.kms.model.*
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import java.lang.reflect.Proxy
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import kotlin.test.*

/** Exercises the actual provider at the AWS SDK boundary; no real AWS account is required. */
class AwsManagedKeyCreationRecoveryTest {
    @Test fun atomicCreateTagsRecoverLostResponseBeforeAliasWithoutASecondCreate() = runTest {
        val f = Fixture(); f.failAfterCreate = true
        val first = f.provider()
        try { assertFailsWith<IllegalStateException> { withContext(f.attempt()) { first.generateKeyAsync(ALIAS, null, null, ALG, null) } } }
        finally { first.close() }
        assertEquals(1, f.creates); assertEquals(0, f.aliases); assertEquals(ManagedKeyCreationAttemptState.CLAIMED, f.state)
        assertEquals(TOKEN, f.createdTags.single { it.tagKey == MANAGED_OPERATION_TAG }.tagValue)
        assertEquals(MANAGED_OPERATION_PURPOSE, f.createdTags.single { it.tagKey == MANAGED_OPERATION_PURPOSE_TAG }.tagValue)
        f.failAfterCreate = false; f.paginate = true
        val restarted = f.provider()
        try {
            val recovered = withContext(f.attempt()) { restarted.generateKeyAsync(ALIAS, null, null, ALG, null) }
            assertEquals(KEY, recovered.kid); assertEquals(ALIAS, recovered.alias)
            assertEquals(1, f.creates); assertEquals(1, f.claims); assertTrue(f.keyPages >= 2); assertTrue(f.tagPages >= 2)
            val read = withContext(f.attempt()) { restarted.getKey(KeyInfo<KeyType>(alias = ALIAS, signatureAlgorithm = ALG)) }
            val readPublic = assertIs<Jwk>(read.key)
            assertEquals(recovered.jose.publicJwk.toJsonObject(), readPublic.toJsonObject())
            assertEquals(KEY, readPublic.kid); assertEquals(ALG.jose, readPublic.alg)
        } finally { restarted.close() }
    }
    @Test fun claimedButInvisibleKeyIsUncertainAndCannotGenerateOrConfirmAbsence() = runTest {
        val f = Fixture(); f.state = ManagedKeyCreationAttemptState.CLAIMED
        val provider = f.provider()
        try {
            assertFailsWith<ManagedKeyCreationUncertainException> { withContext(f.attempt()) { provider.getKey(KeyInfo<KeyType>(alias = ALIAS, signatureAlgorithm = ALG)) } }
            assertFailsWith<ManagedKeyCreationUncertainException> { withContext(f.attempt()) { provider.generateKeyAsync(ALIAS, null, null, ALG, null) } }
            assertEquals(0, f.creates); assertEquals(0, f.claims)
        } finally { provider.close() }
    }
    @Test fun lostClaimResponseDoesNotCreateAndReplayCannotRegainCreationPermission() = runTest {
        val f = Fixture(); f.failClaimResponse = true
        val provider = f.provider()
        try {
            assertFailsWith<IllegalStateException> { withContext(f.attempt()) { provider.generateKeyAsync(ALIAS, null, null, ALG, null) } }
            f.failClaimResponse = false
            assertFailsWith<ManagedKeyCreationUncertainException> { withContext(f.attempt()) { provider.generateKeyAsync(ALIAS, null, null, ALG, null) } }
            assertEquals(0, f.creates); assertEquals(1, f.claims)
        } finally { provider.close() }
    }
    @Test fun tagReadErrorsDuplicateReceiptsAndWrongKeyPurposeCannotAuthorizeCreation() = runTest {
        for (mode in listOf("tags-error", "duplicates", "wrong-purpose", "bad-pagination")) {
            val f = Fixture(); f.physical = true; f.state = ManagedKeyCreationAttemptState.CLAIMED; f.mode = mode
            val provider = f.provider()
            try {
                assertFails { withContext(f.attempt()) { provider.generateKeyAsync(ALIAS, null, null, ALG, null) } }
                assertEquals(0, f.creates)
            } finally { provider.close() }
        }
    }
    @Test fun revokedOrMismatchedContextNeverCallsCreate() = runTest {
        val f = Fixture(); f.state = ManagedKeyCreationAttemptState.REVOKED
        val provider = f.provider()
        try {
            assertFails { withContext(f.attempt()) { provider.generateKeyAsync(ALIAS, null, null, ALG, null) } }
            assertFails { withContext(f.attempt(alias = "foreign-alias")) { provider.generateKeyAsync(ALIAS, null, null, ALG, null) } }
            assertEquals(0, f.creates); assertEquals(0, f.claims)
        } finally { provider.close() }
    }
    @Test fun unclaimedPhysicalAbsenceIsTypedButTransportFailureIsNotAbsence() = runTest {
        val f = Fixture(); val provider = f.provider()
        try {
            assertFailsWith<com.sphereon.core.api.error.NotFoundException> { withContext(f.attempt()) { provider.getKey(KeyInfo<KeyType>(alias = ALIAS, signatureAlgorithm = ALG)) } }
            f.mode = "get-error"
            assertFailsWith<IllegalStateException> { withContext(f.attempt()) { provider.getKey(KeyInfo<KeyType>(alias = ALIAS, signatureAlgorithm = ALG)) } }
            assertEquals(0, f.creates); assertEquals(0, f.claims)
        } finally { provider.close() }
    }

    @Test fun scheduleSuccessThenRestartCompletesPendingDeletionWithoutSecondSchedule() = runTest {
        val f = Fixture(); f.physical = true; f.state = ManagedKeyCreationAttemptState.CLAIMED
        val key = KeyInfo<KeyType>(alias = ALIAS, kid = KEY, providerId = PROVIDER, signatureAlgorithm = ALG)
        val provider = f.provider()
        try {
            assertTrue(withContext(f.attempt(intent = ManagedKeyCreationAttemptIntent.RECOVER_FOR_REVOCATION)) { provider.deleteKey(key) })
            assertEquals(1, f.schedules)
        } finally { provider.close() }
        val restarted = f.provider()
        try {
            assertTrue(withContext(f.attempt(intent = ManagedKeyCreationAttemptIntent.RECOVER_FOR_REVOCATION)) { restarted.deleteKey(key) })
            assertEquals(1, f.schedules)
            f.authorized = false
            assertFails { withContext(f.attempt(intent = ManagedKeyCreationAttemptIntent.RECOVER_FOR_REVOCATION)) { restarted.deleteKey(key) } }
            assertEquals(1, f.schedules)
        } finally { restarted.close() }
    }
    @Test fun pendingDeletionCanConfirmRevocationButCannotReturnSigningMaterial() = runTest {
        val f = Fixture(); f.physical = true; f.pendingDeletion = true; f.state = ManagedKeyCreationAttemptState.CLAIMED
        val provider = f.provider()
        try {
            assertFails { withContext(f.attempt()) { provider.getKey(KeyInfo<KeyType>(alias = ALIAS, signatureAlgorithm = ALG)) } }
            assertEquals(0, f.revocationReports)
            assertFailsWith<ManagedKeyCreationAlreadyRevokedException> {
                withContext(f.attempt(intent = ManagedKeyCreationAttemptIntent.RECOVER_FOR_REVOCATION)) {
                    provider.getKey(KeyInfo<KeyType>(alias = ALIAS, signatureAlgorithm = ALG))
                }
            }
            assertEquals(1, f.revocationReports); assertEquals(0, f.creates); assertEquals(0, f.schedules)
        } finally { provider.close() }
    }
    @Test fun revocationTagMismatchAndProviderErrorsCannotScheduleOrConfirmCleanup() = runTest {
        for (mode in listOf("wrong-tags", "tags-error")) {
            val f = Fixture(); f.physical = true; f.state = ManagedKeyCreationAttemptState.CLAIMED; f.mode = mode
            val provider = f.provider()
            try {
                assertFails { withContext(f.attempt(intent = ManagedKeyCreationAttemptIntent.RECOVER_FOR_REVOCATION)) {
                    provider.deleteKey(KeyInfo<KeyType>(alias = ALIAS, kid = KEY, signatureAlgorithm = ALG))
                } }
                assertEquals(0, f.schedules); assertEquals(0, f.revocationReports)
            } finally { provider.close() }
        }
    }
    @Test fun productionCreateClientDisablesSdkRetriesAndPreservesTheOwningConfiguration() {
        val credentials = aws.sdk.kotlin.runtime.auth.credentials.StaticCredentialsProvider { accessKeyId = "test"; secretAccessKey = "test" }
        val original = KmsClient { region = "eu-central-1"; credentialsProvider = credentials }
        try {
            singleAttemptManagedCreationClient(original).use { scoped ->
                assertEquals(1, scoped.config.retryStrategy.config.maxAttempts)
                assertEquals(original.config.region, scoped.config.region)
                assertSame(original.config.credentialsProvider, scoped.config.credentialsProvider)
                assertSame(original.config.httpClient, scoped.config.httpClient)
            }
        } finally { original.close() }
    }
    @Test fun revocationOnlyCapabilityCannotClaimNewPhysicalCreation() = runTest {
        val f = Fixture(); val provider = f.provider()
        try {
            assertFails { withContext(f.attempt(intent = ManagedKeyCreationAttemptIntent.RECOVER_FOR_REVOCATION)) {
                provider.generateKeyAsync(ALIAS, null, null, ALG, null)
            } }
            assertEquals(0, f.claims); assertEquals(0, f.creates)
        } finally { provider.close() }
    }
    @Test fun unclaimedRevocationReportsOnlyExactTypedPhysicalAbsence() = runTest {
        val f = Fixture(); val provider = f.provider()
        try {
            assertFailsWith<com.sphereon.core.api.error.NotFoundException> {
                withContext(f.attempt(intent = ManagedKeyCreationAttemptIntent.RECOVER_FOR_REVOCATION)) {
                    provider.getKey(KeyInfo<KeyType>(alias = ALIAS, kid = "untrusted-selector", signatureAlgorithm = ALG))
                }
            }
            assertEquals("alias/$ALIAS", f.lastPublicKeyLookup)
            assertEquals(1, f.revocationReports); assertEquals(0, f.creates); assertEquals(0, f.claims)
        } finally { provider.close() }
    }
    @Test fun unclaimedRevocationTransportFailureNeverReportsConclusiveCleanup() = runTest {
        val f = Fixture(); f.mode = "get-error"; val provider = f.provider()
        try {
            assertFailsWith<IllegalStateException> {
                withContext(f.attempt(intent = ManagedKeyCreationAttemptIntent.RECOVER_FOR_REVOCATION)) {
                    provider.getKey(KeyInfo<KeyType>(alias = ALIAS, signatureAlgorithm = ALG))
                }
            }
            assertEquals(0, f.revocationReports); assertEquals(0, f.creates); assertEquals(0, f.claims)
        } finally { provider.close() }
    }
    private class Fixture {
        var state = ManagedKeyCreationAttemptState.UNCLAIMED
        var physical = false; var failAfterCreate = false; var failClaimResponse = false; var paginate = false
        var mode = ""; var creates = 0; var aliases = 0; var claims = 0; var keyPages = 0; var tagPages = 0
        var schedules = 0; var pendingDeletion = false; var revocationReports = 0; var authorized = true
        var createdTags = emptyList<Tag>()
        var lastPublicKeyLookup: String? = null
        private val publicDer = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair().public.encoded
        fun attempt(alias: String = ALIAS, intent: ManagedKeyCreationAttemptIntent = ManagedKeyCreationAttemptIntent.CREATE_OR_RECOVER) = ManagedKeyCreationAttempt(PROVIDER, alias, TOKEN,
            readState = { state }, claim = {
                claims++
                if (state != ManagedKeyCreationAttemptState.UNCLAIMED) false
                else { state = ManagedKeyCreationAttemptState.CLAIMED; if (failClaimResponse) error("lost claim response"); true }
            }, recover = { authorized && state != ManagedKeyCreationAttemptState.REVOKED }, intent = intent,
            confirmRevoked = { check(authorized); revocationReports++ })
        fun provider() = AwsKmsCryptoProvider(settings(), client) { sdk, request -> sdk.createKey(request) }
        private val client = Proxy.newProxyInstance(KmsClient::class.java.classLoader, arrayOf(KmsClient::class.java)) { _, method, args ->
            when (val request = args?.firstOrNull()) {
                is CreateKeyRequest -> {
                    creates++; createdTags = request.tags.orEmpty(); physical = true
                    if (failAfterCreate) error("lost create response")
                    CreateKeyResponse { keyMetadata = metadata(KEY) }
                }
                is CreateAliasRequest -> { aliases++; CreateAliasResponse {} }
                is GetPublicKeyRequest -> {
                    lastPublicKeyLookup = request.keyId
                    if (mode == "get-error") error("transport unavailable")
                    if (!physical || request.keyId?.startsWith("alias/") == true) throw NotFoundException { message = "missing" }
                    GetPublicKeyResponse { keyId = ARN; publicKey = publicDer }
                }
                is ListKeysRequest -> {
                    keyPages++
                    ListKeysResponse {
                        if (!physical) keys = emptyList()
                        else if (mode == "bad-pagination") { keys = emptyList(); truncated = true }
                        else if (paginate && request.marker == null) {
                            keys = listOf(KeyListEntry { keyId = "unrelated-key" }); truncated = true; nextMarker = "keys-next"
                        } else keys = listOf(KeyListEntry { keyId = KEY }) +
                            if (mode == "duplicates") listOf(KeyListEntry { keyId = "second-key" }) else emptyList()
                    }
                }
                is ListResourceTagsRequest -> {
                    tagPages++
                    if (mode == "tags-error") error("tag permission denied")
                    ListResourceTagsResponse {
                        if (request.keyId == "unrelated-key") tags = emptyList()
                        else if (paginate && request.marker == null) {
                            tags = listOf(Tag { tagKey = "unrelated"; tagValue = "value" }); truncated = true; nextMarker = "tags-next"
                        } else tags = listOf(Tag { tagKey = MANAGED_OPERATION_TAG; tagValue = if (mode == "wrong-tags") "foreign" else TOKEN },
                            Tag { tagKey = MANAGED_OPERATION_PURPOSE_TAG; tagValue = MANAGED_OPERATION_PURPOSE })
                    }
                }
                is DescribeKeyRequest -> DescribeKeyResponse { keyMetadata = metadata(request.keyId!!) }
                is ScheduleKeyDeletionRequest -> { schedules++; pendingDeletion = true; ScheduleKeyDeletionResponse { keyState = KeyState.PendingDeletion } }
                else -> when (method.name) { "close" -> Unit; "toString" -> "ManagedCreationAwsFixture"; "hashCode" -> 0; "equals" -> false; else -> error(method.name) }
            }
        } as KmsClient
        private fun metadata(id: String) = KeyMetadata {
            keyId = id; arn = if (id == KEY) ARN else "arn:aws:kms:eu-central-1:123456789012:key/$id"
            enabled = !pendingDeletion; keyState = if (pendingDeletion) KeyState.PendingDeletion else KeyState.Enabled; keySpec = KeySpec.EccNistP256
            keyUsage = if (mode == "wrong-purpose") KeyUsageType.KeyAgreement else KeyUsageType.SignVerify
            origin = OriginType.AwsKms; keyManager = KeyManagerType.Customer
        }
        private fun settings() = KeyProviderSettings(id = PROVIDER, config = KeyProviderConfig(type = KeyProviderType.AWS_KMS,
            aws = AwsKmsClientConfig(region = "eu-central-1", credentialOpts = CredentialOpts(credentialMode = CredentialMode.ACCESS_KEY,
                accessKeyCredentialOpts = AccessKeyCredentialOpts(credentialsSecretId = "test", accessKeyId = "test", secretAccessKey = "test")))))
    }
    private companion object {
        const val PROVIDER = "aws-managed-creation-test"; const val ALIAS = "durable-operation-test"
        const val KEY = "79da999a-1b2c-4d5e-8f90-a1b2c3d4e5f6"
        const val ARN = "arn:aws:kms:eu-central-1:123456789012:key/$KEY"
        const val TOKEN = "f643a15a-61e6-4e03-9ee5-0e50a3afcc19"
        val ALG = SignatureAlgorithm.ECDSA_SHA256
    }
}
