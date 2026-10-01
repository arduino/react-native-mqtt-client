package com.github.emotokcak.reactnative.mqtt

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.io.ByteArrayOutputStream
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/**
 * Builds a PKCS#10 certificate signing request for an EC P-256 key generated
 * in the Android key store, so the private key never leaves secure hardware.
 */
object CertificateSigningRequest {
    // 2.5.4.3
    private val OID_COMMON_NAME = byteArrayOf(0x06, 0x03, 0x55, 0x04, 0x03)

    // 1.2.840.10045.4.3.2
    private val OID_ECDSA_WITH_SHA256 = bytes(0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02)

    private val INTEGER_ZERO = byteArrayOf(0x02, 0x01, 0x00)

    // [0] with no attribute
    private val EMPTY_ATTRIBUTES = bytes(0xA0, 0x00)

    /**
     * Generates a key pair under `keyTag`, replacing any key stored under the
     * same alias, and returns a PEM CSR for it with `commonName` as subject.
     */
    @JvmStatic
    fun generate(commonName: String, keyTag: String): String {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        if (keyStore.containsAlias(keyTag)) {
            keyStore.deleteEntry(keyTag)
        }
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        generator.initialize(
                KeyGenParameterSpec.Builder(keyTag, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
                        .setDigests(
                                KeyProperties.DIGEST_SHA256,
                                KeyProperties.DIGEST_SHA384,
                                KeyProperties.DIGEST_SHA512,
                                KeyProperties.DIGEST_NONE
                        )
                        .setKeySize(256)
                        .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                        .build()
        )
        val keyPair = generator.generateKeyPair()

        val info = sequence(
                INTEGER_ZERO,
                sequence(set(sequence(OID_COMMON_NAME, tlv(0x0C, commonName.toByteArray(Charsets.UTF_8))))),
                // Already a DER SubjectPublicKeyInfo.
                keyPair.public.encoded,
                EMPTY_ATTRIBUTES
        )
        val signer = Signature.getInstance("SHA256withECDSA")
        signer.initSign(keyPair.private)
        signer.update(info)
        val csr = sequence(info, sequence(OID_ECDSA_WITH_SHA256), bitString(signer.sign()))

        val body = Base64.encodeToString(csr, Base64.NO_WRAP).chunked(64).joinToString("\n")
        return "-----BEGIN CERTIFICATE REQUEST-----\n$body\n-----END CERTIFICATE REQUEST-----\n"
    }

    private fun bytes(vararg values: Int) = ByteArray(values.size) { values[it].toByte() }

    private fun sequence(vararg items: ByteArray) = tlv(0x30, concat(items))

    private fun set(vararg items: ByteArray) = tlv(0x31, concat(items))

    private fun bitString(value: ByteArray) = tlv(0x03, byteArrayOf(0x00) + value)

    private fun concat(items: Array<out ByteArray>): ByteArray {
        val out = ByteArrayOutputStream()
        items.forEach { out.write(it) }
        return out.toByteArray()
    }

    private fun tlv(tag: Int, value: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(tag)
        val length = value.size
        if (length < 0x80) {
            out.write(length)
        } else {
            val lengthBytes = generateSequence(length) { (it shr 8).takeIf { rest -> rest > 0 } }
                    .map { (it and 0xFF).toByte() }
                    .toList()
                    .reversed()
            out.write(0x80 or lengthBytes.size)
            out.write(lengthBytes.toByteArray())
        }
        out.write(value)
        return out.toByteArray()
    }
}
