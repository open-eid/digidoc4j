package ee.sk.digidoc4j;

import org.apache.commons.lang.StringUtils;
import org.bouncycastle.util.encoders.Hex;

import java.io.File;
import java.io.FileInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


/**
 * Wrapper for OpenSSL X509 certificate structure.
 */
public class X509Cert {
  private X509Certificate originalCert;
  private Map<String, String> partMap;

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

  /**
   * Key usage
   */
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
    originalCert = cert;
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
   * @param path X509 certificate path
   * @throws Exception throws an exception if the X509 certificate parsing fails
   */
  X509Cert(String path) throws Exception {
    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
    originalCert = (X509Certificate) certificateFactory.generateCertificate(new FileInputStream(new File(path)));
  }

  /**
   * Copy constructor
   *
   * @param sourceCertificate instance of the X509Cert class to be copied
   */
  public X509Cert(X509Cert sourceCertificate) {
    originalCert = sourceCertificate.getX509Certificate();
  }


  /**
   * Returns current certificate policies
   *
   * @return list of policies
   */
  public List<String> getCertificatePolicies() {
    return null;
  }


  /**
   * Returns the internal getX509Certificate of the certificate
   */
  public X509Certificate getX509Certificate() {
    return originalCert;
  }


  /**
   * Retrieves part of the issuer name (for example if set to CN it returns the Common Name part)
   *
   * @param part sets part of issuer name to return
   * @return part of issuer name
   */
  public String issuerName(Issuer part) {
    if (partMap == null) loadIssuerParts();
    return partMap.get(part.name());
  }

  private void loadIssuerParts() {
    String[] parts = StringUtils.split(issuerName(), ',');
    partMap = new HashMap<String, String>();
    for (int i = 0; i < parts.length; i++) {
      String[] strings = StringUtils.split(parts[i], "=");
      partMap.put(strings[0].trim(), strings[1].trim());
    }
  }

  /**
   * Reads the the whole issuer name from X.509 certificate
   *
   * @return issuerName
   */
  public String issuerName() {
    return originalCert.getIssuerDN().getName();
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
   * Reads serial number from X.509 certificate
   *
   * @returns serial number of the X.509 certificate
   */
  public String getSerial() {
    return Hex.toHexString(originalCert.getSerialNumber().toByteArray());
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


  public enum Issuer {
    EMAILADDRESS,
    C,
    O,
    CN;
  }
}
