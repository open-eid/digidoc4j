/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.testutils;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.X509Cert;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.signers.PKCS12SignatureToken;

public class TestSigningHelper {

    public static final String TEST_PKI_CONTAINER = "src/test/resources/testFiles/p12/signout.p12";
    public static final String TEST_PKI_CONTAINER_PASSWORD = "test";
    public static final String TEST_ECC_PKI_CONTAINER = "src/test/resources/testFiles/p12/MadDogOY.p12";
    public static final String TEST_ECC_PKI_CONTAINER_PASSWORD = "test";

    public static X509Certificate getSigningCert() {
        return getSigningCert(TEST_PKI_CONTAINER, TEST_PKI_CONTAINER_PASSWORD);
    }

    public static X509Certificate getSigningCertECC() {
        PKCS12SignatureToken token = new PKCS12SignatureToken(TEST_ECC_PKI_CONTAINER, TEST_ECC_PKI_CONTAINER_PASSWORD, X509Cert.KeyUsage.NON_REPUDIATION);
        String alias = token.getAlias();
        return getSigningCert(TEST_ECC_PKI_CONTAINER, TEST_ECC_PKI_CONTAINER_PASSWORD, alias);
    }

    public static X509Certificate getSigningCert(String pkiContainer, String pkiContainerPassword) {
        return getSigningCert(pkiContainer, pkiContainerPassword, "1");
    }

    public static X509Certificate getSigningCert(String pkiContainer, String pkiContainerPassword, String alias) {
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (FileInputStream stream = new FileInputStream(pkiContainer)) {
                keyStore.load(stream, pkiContainerPassword.toCharArray());
            }
            return (X509Certificate) keyStore.getCertificate(alias);
        } catch (Exception e) {
            throw new DigiDoc4JException("Loading signer cert failed; " + e.getMessage());
        }
    }

    public static byte[] sign(byte[] dataToSign, DigestAlgorithm digestAlgorithm) {
        PKCS12SignatureToken token = new PKCS12SignatureToken(TEST_PKI_CONTAINER, TEST_PKI_CONTAINER_PASSWORD,
            X509Cert.KeyUsage.NON_REPUDIATION);
        return token.sign(digestAlgorithm, dataToSign);
    }

    public static byte[] signECC(byte[] dataToSign, DigestAlgorithm digestAlgorithm) {
        PKCS12SignatureToken token = new PKCS12SignatureToken(TEST_ECC_PKI_CONTAINER, TEST_ECC_PKI_CONTAINER_PASSWORD,
            X509Cert.KeyUsage.NON_REPUDIATION);
        return token.sign(digestAlgorithm, dataToSign);
    }
}
