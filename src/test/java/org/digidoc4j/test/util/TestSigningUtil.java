/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.test.util;

import java.io.FileInputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;

import org.apache.commons.lang3.ArrayUtils;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.X509Cert;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.signers.PKCS12SignatureToken;

public class TestSigningUtil {

  public static final String TEST_PKI_CONTAINER = "src/test/resources/testFiles/p12/signout.p12";
  public static final String TEST_PKI_CONTAINER_PASSWORD = "test";
  public static final String TEST_ECC_PKI_CONTAINER = "src/test/resources/testFiles/p12/MadDogOY.p12";
  public static final String TEST_ECC_PKI_CONTAINER_PASSWORD = "test";

  public static X509Certificate getSigningCertificate() {
    return TestSigningUtil.getSigningCertificate(TEST_PKI_CONTAINER, TEST_PKI_CONTAINER_PASSWORD);
  }

  public static X509Certificate getSigningCertECC() {
    PKCS12SignatureToken token = new PKCS12SignatureToken(TEST_ECC_PKI_CONTAINER, TEST_ECC_PKI_CONTAINER_PASSWORD, X509Cert.KeyUsage.NON_REPUDIATION);
    return TestSigningUtil.getSigningCertificate(TEST_ECC_PKI_CONTAINER, TEST_ECC_PKI_CONTAINER_PASSWORD, token.getAlias());
  }

  public static X509Certificate getSigningCertificate(String pkiContainer, String pkiContainerPassword) {
    return TestSigningUtil.getSigningCertificate(pkiContainer, pkiContainerPassword, "1");
  }

  public static X509Certificate getSigningCertificate(String pkiContainer, String pkiContainerPassword, String alias) {
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

  /**
   * This method digest and encrypt the given {@code InputStream} with indicated private key and signature algorithm. To find the signature object
   * the list of registered security Providers, starting with the most preferred Provider is traversed.
   *
   * This method returns an array of bytes representing the signature value. Signature object that implements the specified signature algorithm. It traverses the list of
   * registered security Providers, starting with the most preferred Provider. A new Signature object encapsulating the SignatureSpi implementation from the first Provider
   * that supports the specified algorithm is returned. The {@code NoSuchAlgorithmException} exception is wrapped in a DSSException.
   *
   * @param signatureAlgorithm signature algorithm under JAVA form.
   * @param privateKey             private key to use
   * @param bytes                  the data to digest
   * @return digested and encrypted array of bytes
   */
  @Deprecated
  public static byte[] encrypt(String signatureAlgorithm, PrivateKey privateKey, byte[] bytes) {
    try {
      Signature signature = Signature.getInstance(signatureAlgorithm);
      signature.initSign(privateKey);
      signature.update(bytes);
      return signature.sign();
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    }
  }

  public static byte[] addPadding(byte[] digest) {
    return ArrayUtils.addAll(DigestAlgorithm.SHA256.digestInfoPrefix(), digest);
  }

}
