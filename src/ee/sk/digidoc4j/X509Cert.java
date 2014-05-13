package ee.sk.digidoc4j;

import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;


/**
 * Wrapper for OpenSSL X509 certificate structure
 */
public class X509Cert {
  /**
   * Binary encoding format
   */
  public enum Format {
    /**
     * ASN.1 syntax
     */
    DER,
    /**
     * Base64 encoded ASN.1 syntax
     */
    PEM;
  }

  public enum KeyUsage {
    DIGITAL_SIGNATURE,
    /**
     * Used for signing certificate selection in the current library
     */
    NON_REPUDIATION,
    KEY_ENCIPHERMENT,
    DATA_ENCIPHERMENT,
    KEY_AGREEMENT,
    KEY_CERTIFICATESIGN,
    CRL_SIGN,
    ENCIPHER_ONLY,
    DECIPHER_ONLY;
  }

  /**
   * Creates a copy of the X509Certificate
   *
   * @param cert X509 certificate to be wrapped
   */
  public X509Cert(X509Certificate cert) {
  }

  /**
   * Creates an X509 certificate from bytes
   *
   * @param bytes  X509 certificate in bytes
   * @param format input bytes format
   * @throws Exception throws an exception if the X509 certificate parsing fails
   */
  public X509Cert(byte[] bytes, Format format) throws Exception {
  }

  /**
   * Creates an X509 certificate from a path
   *
   * @param path   X509 certificate path
   * @param format input bytes format
   * @throws Exception throws an exception if the X509 certificate parsing fails
   */
  X509Cert(String path, Format format) throws Exception {
  }

  /**
   * Copy constructor
   *
   * @param sourceCertificate instance of the X509Cert class to be copied
   */
  public X509Cert(X509Cert sourceCertificate) {
  }


  /**
   * Returns current certificate policies
   */
  public List<String> getCertificatePolicies() {
    return null;
  }


  /**
   * Returns the internal getX509Certificate of the certificate
   */
  public X509Certificate getX509Certificate() {
    return null;
  }


  /**
   * Returns part of the issuer name (for example if set to CN it returns the Common Name part)
   *
   * @param part sets part of issuer name to return
   * @throws Exception thrown if the conversion failed
   */
  public String issuerName(String part) throws Exception {
    return null;
  }

  /**
   * Returns the the whole issuer name
   *
   * @throws Exception thrown if the conversion failed
   */
  public String issuerName() throws Exception {
    return null;
  }

  /**
   * Validates if the certificate is in a valid time slot
   *
   * @param date sets date to compare
   */
  public boolean isValid(Date date) {
    return false;
  }

  /**
   * Validates if the certificate is valid now
   */
  public boolean isValid() {
    return false;
  }

  /**
   * Returns the current certificate key usage bits
   */
  public List<X509Cert> getKeyUsages() {
    return null;
  }

  /**
   * Returns the getSerial number of the X.509 certificate
   *
   * @throws Exception thrown if the serial is incorrect
   */
  public String getSerial() throws Exception {
    return null;
  }

  /**
   * Returns part of the subject name (for example if set to CN it returns the Common Name part)
   *
   * @param part sets part of subject name to return
   * @throws Exception thrown if the conversion failed
   */
  public String getSubjectName(String part) throws Exception {
    return null;
  }

  /**
   * Returns the whole subject name as a string
   *
   * @throws Exception thrown if the conversion failed
   */
  public String getSubjectName() throws Exception {
    return null;
  }


}
