package taco.authorization.server

import com.nimbusds.jose.jwk.RSAKey
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.*

object KeyGeneratorUtils {

    fun generateRsaKey(): RSAKey {
        val keyPair: KeyPair = generateRsaKeyPair()
        val publicKey = keyPair.public as RSAPublicKey
        val privateKey = keyPair.private as RSAPrivateKey

        return RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(UUID.randomUUID().toString())
            .build()
    }

    private fun generateRsaKeyPair(): KeyPair = kotlin.runCatching {
        KeyPairGenerator.getInstance("RSA")
            .let { keyPairGenerator -> keyPairGenerator.initialize(2048)
                return@runCatching keyPairGenerator.generateKeyPair()
            }
    }.getOrElse { exception ->  throw IllegalStateException(exception) }

}