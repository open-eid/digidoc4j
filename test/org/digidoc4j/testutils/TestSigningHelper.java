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
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.apache.commons.lang.ArrayUtils;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.exceptions.DigiDoc4JException;

import prototype.samples.AsyncSigning;

public class TestSigningHelper {

  public static final String TEST_PKI_CONTAINER = "testFiles/signout.p12";
  public static final String TEST_PKI_CONTAINER_PASSWORD = "test";

  public static X509Certificate getSigningCert() {
    try {
      KeyStore keyStore = KeyStore.getInstance("PKCS12");
      try (FileInputStream stream = new FileInputStream(TEST_PKI_CONTAINER)) {
        keyStore.load(stream, TEST_PKI_CONTAINER_PASSWORD.toCharArray());
      }
      return (X509Certificate) keyStore.getCertificate("1");
    } catch (Exception e) {
      throw new DigiDoc4JException("Loading signer cert failed");
    }
  }

  public static byte[] sign(byte[] dataToSign, DigestAlgorithm digestAlgorithm) {
    try {
      KeyStore keyStore = KeyStore.getInstance("PKCS12");
      try (FileInputStream stream = new FileInputStream("testFiles/signout.p12")) {
        keyStore.load(stream, "test".toCharArray());
      }
      PrivateKey privateKey = (PrivateKey) keyStore.getKey("1", "test".toCharArray());
      final String javaSignatureAlgorithm = "NONEwith" + privateKey.getAlgorithm();

      return AsyncSigning.encrypt(javaSignatureAlgorithm, privateKey, addPadding(dataToSign, digestAlgorithm));
    } catch (Exception e) {
      throw new DigiDoc4JException("Loading private key failed");
    }
  }

  private static byte[] addPadding(byte[] digest, DigestAlgorithm digestAlgorithm) {
    return ArrayUtils.addAll(digestAlgorithm.digestInfoPrefix(), digest);
  }
}
