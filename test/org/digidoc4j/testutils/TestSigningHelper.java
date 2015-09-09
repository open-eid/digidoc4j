package org.digidoc4j.testutils;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.apache.commons.lang.ArrayUtils;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.utils.DigestInfoPrefix;

import eu.europa.ec.markt.dss.DSSUtils;

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

      return DSSUtils.encrypt(javaSignatureAlgorithm, privateKey, addPadding(dataToSign, digestAlgorithm));
    } catch (Exception e) {
      throw new DigiDoc4JException("Loading private key failed");
    }
  }

  private static byte[] addPadding(byte[] digest, DigestAlgorithm digestAlgorithm) {
    return ArrayUtils.addAll(DigestInfoPrefix.getDigestInfoPrefix(digestAlgorithm), digest);
  }
}
