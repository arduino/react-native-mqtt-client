package com.github.emotokcak.reactnative.mqtt

import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/** Utility to read a certificate and key from a PEM text. */
object PEMLoader {
    /**
     * Loads an X.509 certificate from a given PEM text.
     *
     * `pem` has to start with "-----BEGIN CERTIFICATE-----"
     * and end with "-----END CERTIFICATE-----".
     *
     * @param pem
     *
     *   PEM representation of a certificate.
     *
     * @throws CertificateException
     *
     *   If `pem` is invalid.
     */
    @JvmStatic
    fun loadX509CertificateFromString(pem: String): X509Certificate {
        val certificateFactory = CertificateFactory.getInstance("X.509")
        return certificateFactory.generateCertificate(pem.byteInputStream())
                as X509Certificate
    }
}
