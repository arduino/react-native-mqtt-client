package com.github.emotokcak.reactnative.mqtt

import java.net.Socket
import java.security.KeyStore
import java.security.Principal
import java.security.PrivateKey
import java.security.cert.X509Certificate
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509ExtendedKeyManager
import javax.net.ssl.X509KeyManager

/** Utility to configures an `SSLSocketFactory`. */
object SSLSocketFactoryUtil {
    private const val SSL_PROTOCOL: String = "TLS"

    private const val PASSWORD: String = ""

    /**
     * Loads the private key from the Keystore.
     *
     * @param keyTag
     *
     *   key tag of the private key in Keystore
     */
    @JvmStatic
    fun loadPrivateKeyFromKeystore(keyTag: String): PrivateKey {
        val ks = KeyStore.getInstance("AndroidKeyStore")
        ks.load(null)
        val entry: KeyStore.Entry = ks.getEntry(keyTag, null)
        return (entry as KeyStore.PrivateKeyEntry).privateKey
    }

    /**
     * Creates an `SSLSocketFactory` with given certificates.
     *
     * @param caCertPem
     *
     *   PEM representation of a root certificate.
     *
     * @param certPem
     *
     *   PEM representation of a certificate.
     *
     * @param keyTag
     *
     *   key tag of the private key in Keystore.
     *
     * @param caCertAlias
     *
     *   Alias for a root certificate.
     *
     * @param keyAlias
     *
     *   Alias for a private key.
     *
     * @return
     *
     *   `SSLSocketFactory` created with `caCertPem`, `certPem` and `keyTag`.
     *
     * @throws CertificateException
     *
     * @throws InvalidKeySpecException
     *
     * @throws IOException
     *
     * @throws KeyManagementException
     *
     * @throws KeyStoreException
     *
     * @throws NoSuchAlgorithmException
     *
     * @throws UnrecoverableKeyException
     */
    @JvmStatic
    fun createSocketFactory(
            caCertPem: String,
            certPem: String,
            keyTag: String,
            caCertAlias: String,
    ): SSLSocketFactory {
        // Reference: https://gist.github.com/sharonbn/4104301
        val rootCaCert = PEMLoader.loadX509CertificateFromString(caCertPem)
        val clientCert = PEMLoader.loadX509CertificateFromString(certPem)
        val clientKey = loadPrivateKeyFromKeystore(keyTag)
        // certificates and a key saved in the AndroidKeyStore are persisted.
        // please refer to the following section for AndroidKeyStore,
        // https://developer.android.com/training/articles/keystore#UsingAndroidKeyStore
        val androidKeyStore = KeyStore.getInstance("AndroidKeyStore")
        androidKeyStore.load(null)
        // Due to a bug with Android 12 https://issuetracker.google.com/issues/197556146?pli=1
        // we need to pass the same keyTag string to the alias parameter
        // that we use to load the private key from keystore.
        androidKeyStore.setKeyEntry(
                keyTag,
                clientKey,
                PASSWORD.toCharArray(),
                arrayOf(clientCert)
        )
        androidKeyStore.setCertificateEntry(caCertAlias, rootCaCert)
        return this.createSocketFactoryFromAndroidKeyStore(keyTag, caCertAlias)
    }

    /**
     * Creates an `SSLSocketFactory` from the identity stored in the Android
     * key store under `keyAlias`, trusting only the root certificate stored
     * under `caCertAlias`.
     *
     * Other identities in the key store are never presented to the broker.
     *
     * @throws IllegalStateException
     *
     *   If either entry is missing.
     */
    @JvmStatic
    fun createSocketFactoryFromAndroidKeyStore(
            keyAlias: String,
            caCertAlias: String
    ): SSLSocketFactory {
        val androidKeyStore = KeyStore.getInstance("AndroidKeyStore")
        androidKeyStore.load(null)
        val rootCaCert = androidKeyStore.getCertificate(caCertAlias)
                ?: throw IllegalStateException("no root certificate is stored as $caCertAlias")
        if (!androidKeyStore.isKeyEntry(keyAlias)) {
            throw IllegalStateException("no private key is stored as $keyAlias")
        }

        val trustStore = KeyStore.getInstance(KeyStore.getDefaultType())
        trustStore.load(null)
        trustStore.setCertificateEntry(caCertAlias, rootCaCert)
        val trustManagerFactory = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm()
        )
        trustManagerFactory.init(trustStore)

        val keyManagerFactory = KeyManagerFactory.getInstance(
                KeyManagerFactory.getDefaultAlgorithm()
        )
        keyManagerFactory.init(androidKeyStore, PASSWORD.toCharArray())
        val keyManagers = keyManagerFactory.keyManagers
                .filterIsInstance<X509KeyManager>()
                .map { SingleAliasKeyManager(it, keyAlias) }

        val sslContext = SSLContext.getInstance(SSL_PROTOCOL)
        sslContext.init(
                keyManagers.toTypedArray(),
                trustManagerFactory.trustManagers,
                null // default SecureRandom
        )
        return sslContext.socketFactory
    }

    // Presents the identity stored under `alias` and no other.
    private class SingleAliasKeyManager(
            private val delegate: X509KeyManager,
            private val alias: String
    ) : X509ExtendedKeyManager() {
        override fun chooseClientAlias(
                keyType: Array<out String>?,
                issuers: Array<out Principal>?,
                socket: Socket?
        ): String = alias

        override fun chooseEngineClientAlias(
                keyType: Array<out String>?,
                issuers: Array<out Principal>?,
                engine: SSLEngine?
        ): String = alias

        override fun getClientAliases(
                keyType: String?,
                issuers: Array<out Principal>?
        ): Array<String> = arrayOf(alias)

        override fun chooseServerAlias(
                keyType: String?,
                issuers: Array<out Principal>?,
                socket: Socket?
        ): String? = null

        override fun getServerAliases(
                keyType: String?,
                issuers: Array<out Principal>?
        ): Array<String>? = null

        override fun getCertificateChain(alias: String?): Array<X509Certificate>? =
                delegate.getCertificateChain(alias)

        override fun getPrivateKey(alias: String?): PrivateKey? =
                delegate.getPrivateKey(alias)
    }

    /**
     * Clears a root certificate and private key the Android key store.
     *
     * @param caCertAlias
     *
     *   Alias for the root certificate to be cleared.
     *
     * @param keyAlias
     *
     *   Alias for the private key to be cleared.
     *
     * @throws CertificateException
     *
     * @throws IOException
     *
     * @throws KeyStoreException
     *
     * @throws NoSuchAlgorithmException
     */
    fun resetAndroidKeyStore(caCertAlias: String, keyAlias: String) {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        keyStore.deleteEntry(caCertAlias)
        keyStore.deleteEntry(keyAlias)
    }

    /**
     * Returns whether a root certificate and a private key are stored in
     * the Android key store.
     *
     * @param caCertAlias
     *
     *   Alias for a root certificate.
     *
     * @param keyAlias
     *
     *   Alias for a private key.
     *
     * @return
     *
     *   Whether the root certificate and the private key are stored in
     *   the Android key store.
     *
     * @throws CertificateException
     *
     * @throws IOException
     *
     * @throws KeyStoreException
     *
     * @throws NoSuchAlgorithmException
     */
    fun deleteAndroidKeyStoreEntries(prefixes: List<String>, keep: List<String>): Int {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        val doomed = keyStore.aliases().toList().filter { alias ->
            prefixes.any { alias.startsWith(it) } && keep.none { alias.startsWith(it) }
        }
        doomed.forEach { keyStore.deleteEntry(it) }
        return doomed.size
    }

    fun isIdentityStoredInAndroidKeyStore(
            caCertAlias: String,
            keyAlias: String
    ): Boolean {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        return keyStore.isCertificateEntry(caCertAlias) &&
                keyStore.isKeyEntry(keyAlias)
    }
}

