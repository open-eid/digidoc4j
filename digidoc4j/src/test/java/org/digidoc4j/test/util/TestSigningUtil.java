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

import org.apache.commons.lang3.ArrayUtils;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.X509Cert;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.signers.PKCS12SignatureToken;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public final class TestSigningUtil {

  public static final String TEST_PKI_CONTAINER = "src/test/resources/testFiles/p12/sign_RSA_from_TEST_of_ESTEIDSK2015.p12";
  public static final String TEST_PKI_CONTAINER_PASSWORD = "1234";
  public static final String TEST_ECC_PKI_CONTAINER = "src/test/resources/testFiles/p12/MadDogOY.p12";
  public static final String TEST_ECC_PKI_CONTAINER_PASSWORD = "test";
  public static final X509Certificate SIGN_CERT = TestSigningUtil.toX509Certificate("-----BEGIN CERTIFICATE-----\r\n" +
      "MIIEqDCCA5CgAwIBAgIQXZSW5EBkctNPfCkprF2XsTANBgkqhkiG9w0BAQUFADBs\r\n" +
      "MQswCQYDVQQGEwJFRTEiMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1\r\n" +
      "czEfMB0GA1UEAwwWVEVTVCBvZiBFU1RFSUQtU0sgMjAxMTEYMBYGCSqGSIb3DQEJ\r\n" +
      "ARYJcGtpQHNrLmVlMB4XDTEyMDQwNDEwNTc0NFoXDTE1MDQwNDIwNTk1OVowga4x\r\n" +
      "CzAJBgNVBAYTAkVFMRswGQYDVQQKDBJFU1RFSUQgKE1PQklJTC1JRCkxGjAYBgNV\r\n" +
      "BAsMEWRpZ2l0YWwgc2lnbmF0dXJlMSgwJgYDVQQDDB9URVNUTlVNQkVSLFNFSVRT\r\n" +
      "TUVTLDE0MjEyMTI4MDI1MRMwEQYDVQQEDApURVNUTlVNQkVSMREwDwYDVQQqDAhT\r\n" +
      "RUlUU01FUzEUMBIGA1UEBRMLMTQyMTIxMjgwMjUwgZ8wDQYJKoZIhvcNAQEBBQAD\r\n" +
      "gY0AMIGJAoGBAMFo0cOULrm6HHJdMsyYVq6bBmCU4rjg8eonNnbWNq9Y0AAiyIQv\r\n" +
      "J3xDULnfwJD0C3QI8Y5RHYnZlt4U4Yt4CI6JenMySV1hElOtGYP1EuFPf643V11t\r\n" +
      "/mUDgY6aZaAuPLNvVYbeVHv0rkunKQ+ORABjhANCvHaErqC24i9kv3mVAgMBAAGj\r\n" +
      "ggGFMIIBgTAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIGQDCBmQYDVR0gBIGRMIGO\r\n" +
      "MIGLBgorBgEEAc4fAwEBMH0wWAYIKwYBBQUHAgIwTB5KAEEAaQBuAHUAbAB0ACAA\r\n" +
      "dABlAHMAdABpAG0AaQBzAGUAawBzAC4AIABPAG4AbAB5ACAAZgBvAHIAIAB0AGUA\r\n" +
      "cwB0AGkAbgBnAC4wIQYIKwYBBQUHAgEWFWh0dHA6Ly93d3cuc2suZWUvY3BzLzAn\r\n" +
      "BgNVHREEIDAegRxzZWl0c21lcy50ZXN0bnVtYmVyQGVlc3RpLmVlMB0GA1UdDgQW\r\n" +
      "BBSBiUUnibDAPTHAuhRAwSvWzPfoEjAYBggrBgEFBQcBAwQMMAowCAYGBACORgEB\r\n" +
      "MB8GA1UdIwQYMBaAFEG2/sWxsbRTE4z6+mLQNG1tIjQKMEUGA1UdHwQ+MDwwOqA4\r\n" +
      "oDaGNGh0dHA6Ly93d3cuc2suZWUvcmVwb3NpdG9yeS9jcmxzL3Rlc3RfZXN0ZWlk\r\n" +
      "MjAxMS5jcmwwDQYJKoZIhvcNAQEFBQADggEBAKPzonf5auRAC8kX6zQTX0yYeQvv\r\n" +
      "l2bZdbMmDAp07g3CxEaC6bk8DEx9pOJR2Wtm7J9wQke6+HpLEGgNVTAllm+oE4sU\r\n" +
      "VsaIqFmrcqilWqeWIpj5uR/yU4GDDD9jAGFZtOLaFgaGCwE5++q/LZhosyyAGgvD\r\n" +
      "yl+yGm5IxTRQ9uflppNZ7k2LoFkoDJhgqHqMZQjwN1kJQ/VBReCRMGUVj5wkBLTJ\r\n" +
      "o9GcMiugyKQib9I6vV9TdemUXKgL+MYp2S8LeIBt0eUXvpp8n/3HIKJIyJpdVvK1\r\n" +
      "wX5bWYM2o6dT7FAftrkVnShTsEACuRBYSi/4a4hTsSeQTa2Oz1GoNZ7ADXI=\r\n" +
      "-----END CERTIFICATE-----");

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

  public static X509Certificate toX509Certificate(String certificate) {
    try {
      return TestSigningUtil.toX509Certificate(certificate.getBytes());
    } catch (CertificateException e) {
      throw new RuntimeException(e);
    }
  }

  public static byte[] addPadding(byte[] digest) {
    return ArrayUtils.addAll(DigestAlgorithm.SHA256.digestInfoPrefix(), digest);
  }

  /**
   * This method encrypts the given input using the specified private key and signature algorithm, returning an array
   * of bytes representing the signature value.
   * <p>
   * To find the {@link Signature} implementation for the specified signature algorithm, the list of registered security
   * providers, starting with the most preferred provider, is traversed.
   * A new {@link Signature} object encapsulating the {@link java.security.SignatureSpi} implementation from the first
   * provider that supports the specified algorithm is returned.
   *
   * @param signatureAlgorithm signature algorithm name
   * @param privateKey private key to use
   * @param bytes the data to encrypt
   * @return signature bytes
   *
   * @see <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Signature">
   * Standard signature algorithm names</a>
   */
  public static byte[] encrypt(String signatureAlgorithm, PrivateKey privateKey, byte[] bytes) {
    try {
      Signature signature = Signature.getInstance(signatureAlgorithm);
      signature.initSign(privateKey);
      signature.update(bytes);
      return signature.sign();
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("Failed to encrypt", e);
    }
  }

  /**
   * This method encrypts the given input using the specified private key and a signature algorithm derived from the
   * key and the specified digest algorithm.
   * <p>
   * The name of the signature algorithm is constructed as:
   * <pre>{@code
   * digestAlgorithm + "with" + privateKey.getAlgorithm()
   * }</pre>
   *
   * @param privateKey private key to use
   * @param bytes the data to encrypt
   * @param digestAlgorithm digest algorithm name
   * @return signature bytes
   *
   * @see #encrypt(String, PrivateKey, byte[])
   */
  public static byte[] encrypt(PrivateKey privateKey, byte[] bytes, String digestAlgorithm) {
    String signatureAlgorithm = digestAlgorithm + "with" + privateKey.getAlgorithm();
    return encrypt(signatureAlgorithm, privateKey, bytes);
  }

  /**
   * This method encrypts the given input using the specified private key and a signature algorithm derived from the
   * key and the specified digest algorithm.
   *
   * @param privateKey private key to use
   * @param bytes the data to encrypt
   * @param digestAlgorithm digest algorithm
   * @return signature bytes
   *
   * @see #encrypt(PrivateKey, byte[], String)
   */
  public static byte[] encrypt(PrivateKey privateKey, byte[] bytes, eu.europa.esig.dss.enumerations.DigestAlgorithm digestAlgorithm) {
    return encrypt(privateKey, bytes, digestAlgorithm.getName());
  }

  /**
   * This method encrypts the given input using the specified private key and a signature algorithm derived from the
   * key and the specified digest algorithm.
   *
   * @param privateKey private key to use
   * @param bytes the data to encrypt
   * @param digestAlgorithm digest algorithm
   * @return signature bytes
   *
   * @see #encrypt(PrivateKey, byte[], eu.europa.esig.dss.enumerations.DigestAlgorithm)
   */
  public static byte[] encrypt(PrivateKey privateKey, byte[] bytes, DigestAlgorithm digestAlgorithm) {
    return encrypt(privateKey, bytes, digestAlgorithm.getDssDigestAlgorithm());
  }

  /**
   * This method encrypts the given input using the specified private key and a signature algorithm derived from the key.
   * <p>
   * The digest algorithm to be used is {@code NONE}, i.e. the name of the signature algorithm is constructed as:
   * <pre>{@code
   * "NONEwith" + privateKey.getAlgorithm()
   * }</pre>
   *
   * @param privateKey private key to use
   * @param bytes the data to encrypt
   * @return signature bytes
   *
   * @see #encrypt(PrivateKey, byte[], String)
   */
  public static byte[] encrypt(PrivateKey privateKey, byte[] bytes) {
    return encrypt(privateKey, bytes, "NONE");
  }

  /*
   * RESTRICTED METHODS
   */

  private static X509Certificate toX509Certificate(byte[] cert) throws CertificateException {
    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
    synchronized (certificateFactory) {
      return (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(cert));
    }
  }

  private TestSigningUtil() {}

}
