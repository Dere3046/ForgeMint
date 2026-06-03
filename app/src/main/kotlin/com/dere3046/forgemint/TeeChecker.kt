package com.dere3046.forgemint

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom

object TeeChecker {

    private const val TEST_ALIAS = "forgemint_tee_check"

    fun isTeeFunctional(): Boolean {
        return try {
            try {
                KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
                    .deleteEntry(TEST_ALIAS)
            } catch (_: Exception) {}

            val spec = KeyGenParameterSpec.Builder(
                TEST_ALIAS,
                KeyProperties.PURPOSE_SIGN,
            ).apply {
                setDigests(KeyProperties.DIGEST_SHA256)
                setAlgorithmParameterSpec(
                    java.security.spec.ECGenParameterSpec("secp256r1")
                )
                val challenge = ByteArray(32)
                SecureRandom().nextBytes(challenge)
                setAttestationChallenge(challenge)
            }.build()

            val kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                "AndroidKeyStore"
            )
            kpg.initialize(spec)
            kpg.generateKeyPair()

            KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
                .deleteEntry(TEST_ALIAS)

            Logger.i("TEE is functional")
            true
        } catch (e: Exception) {
            Logger.w("TEE not functional: ${e.message}")
            false
        }
    }
}
