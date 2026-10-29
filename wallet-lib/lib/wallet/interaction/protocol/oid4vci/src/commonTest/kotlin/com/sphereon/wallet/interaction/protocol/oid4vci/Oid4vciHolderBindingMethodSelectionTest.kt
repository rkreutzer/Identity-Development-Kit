package com.sphereon.wallet.interaction.protocol.oid4vci

import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.wallet.credential.WalletHolderIdentifierKind
import com.sphereon.wallet.credential.WalletHolderVerificationMethod
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * OID4VCI 1.0 section 12.2.4: `cryptographic_binding_methods_supported` names the key
 * representations the issuer binds a credential to (`jwk`, `did:<method>`); when absent, binding is
 * not required. The wallet satisfies `did:jwk` with the holder key's registered `#0` verification
 * method and `jwk` with the key itself.
 */
class Oid4vciHolderBindingMethodSelectionTest {
    private val didJwkMethod = WalletHolderVerificationMethod(
        value = "did:jwk:eyJrdHkiOiJFQyJ9#0",
        controller = "did:jwk:eyJrdHkiOiJFQyJ9",
        kind = WalletHolderIdentifierKind.DID_VERIFICATION_METHOD,
        signingAlgorithm = SignatureAlgorithm.ECDSA_SHA256,
    )
    private var lookups = 0

    private suspend fun select(methods: List<String>, method: WalletHolderVerificationMethod?) =
        selectHolderDidVerificationMethod(methods) { lookups++; method }

    @Test
    fun offeredDidJwkUsesTheHolderKeysDidJwkVerificationMethod() = runTest {
        assertEquals(didJwkMethod.value, select(listOf("did:jwk"), didJwkMethod).value)
        assertEquals(didJwkMethod.value, select(listOf("jwk", "did:jwk"), didJwkMethod).value)
    }

    @Test
    fun jwkOrNoAdvertisedBindingUsesAJwkProofWithoutLookingUpADid() = runTest {
        assertNull(select(listOf("jwk"), didJwkMethod).value)
        assertNull(select(emptyList(), didJwkMethod).value)
        assertEquals(0, lookups)
    }

    @Test
    fun offeredDidJwkFallsBackToJwkOnlyWhenJwkIsAlsoOffered() = runTest {
        assertNull(select(listOf("did:jwk", "jwk"), null).value)

        val refused = select(listOf("did:jwk"), null)
        assertTrue(refused.isErr)
        assertEquals("oid4vci.holder_binding_method_unsupported", refused.error.code)
    }

    @Test
    fun aRegisteredVerificationMethodThatIsNotDidJwkDoesNotSatisfyDidJwk() = runTest {
        val jwksKid = didJwkMethod.copy(value = "https://holder.example/jwks#k1", controller = "https://holder.example", kind = WalletHolderIdentifierKind.JWKS_KID)
        val otherDid = didJwkMethod.copy(value = "did:key:z6Mk#z6Mk", controller = "did:key:z6Mk")

        assertTrue(select(listOf("did:jwk"), jwksKid).isErr)
        assertTrue(select(listOf("did:jwk"), otherDid).isErr)
    }

    @Test
    fun onlyUnsupportedBindingMethodsFailClosed() = runTest {
        val refused = select(listOf("did:web", "cose_key"), didJwkMethod)

        assertTrue(refused.isErr)
        assertEquals("oid4vci.holder_binding_method_unsupported", refused.error.code)
    }

    @Test
    fun mdocCoseBindingUsesTheSameEmbeddedJwkProofWithoutDidLookup() = runTest {
        val selected = selectHolderDidVerificationMethod(listOf("cose_key"), credentialFormat = "mso_mdoc") {
            lookups++
            didJwkMethod
        }
        assertTrue(selected.isOk)
        assertNull(selected.value)
        assertEquals(0, lookups)
    }

    @Test
    fun coseBindingDoesNotAuthorizeOtherCredentialFormatsOrUnsupportedDids() = runTest {
        for (format in listOf(null, "dc+sd-jwt", "jwt_vc_json")) {
            val selected = selectHolderDidVerificationMethod(listOf("cose_key"), credentialFormat = format) {
                lookups++
                didJwkMethod
            }
            assertTrue(selected.isErr)
            assertEquals("oid4vci.holder_binding_method_unsupported", selected.error.code)
        }
        assertTrue(selectHolderDidVerificationMethod(listOf("did:web"), credentialFormat = "mso_mdoc") { didJwkMethod }.isErr)
        assertEquals(0, lookups)
    }
}
