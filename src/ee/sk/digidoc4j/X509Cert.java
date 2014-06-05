package ee.sk.digidoc4j;

import org.apache.commons.lang.StringUtils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.util.encoders.Hex;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.*;


/**
 * Wrapper for OpenSSL X509 certificate structure.
 */
public class X509Cert {
  private X509Certificate originalCert;
  private Map<String, String> issuerPartMap;
  private Map<String, String> subjectNamePartMap;

  /**
   * Key usage.
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
   * Issuer parts.
   */
  public enum Issuer {
    EMAILADDRESS,
    C,
    O,
    CN;
  }

  /**
   * Subject Name parts.
   */
  public enum SubjectName {
    SERIALNUMBER,
    GIVENNAME,
    SURNAME,
    CN,
    OU,
    O,
    C;
  }


  /**
   * Creates a copy of the X509Certificate.
   *
   * @param cert X509 certificate to be wrapped
   */
  public X509Cert(X509Certificate cert) {
    originalCert = cert;
  }

//  /**
//   * Creates an X509 certificate from bytes.
//   *
//   * @param bytes  X509 certificate in bytes
//   * @param format input bytes format
//   * @throws Exception throws an exception if the X509 certificate parsing fails
//   */
//  public X509Cert(byte[] bytes, Format format) throws Exception {
//  }

  /**
   * Creates an X509 certificate from a path.
   *
   * @param path X509 certificate path
   * @throws Exception throws an exception if the X509 certificate parsing fails
   */
  X509Cert(String path) throws Exception {
    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
    originalCert = (X509Certificate) certificateFactory.generateCertificate(new FileInputStream(new File(path)));
  }

  /**
   * Returns current certificate policies or null if no policies was found.
   *
   * @return list of policies
   * @throws IOException when policy parsing fails
   */
  public List<String> getCertificatePolicies() throws IOException {
    byte[] extensionValue = originalCert.getExtensionValue("2.5.29.32");
    List<String> policies = new ArrayList<String>();

    byte[] octets = ((DEROctetString) DEROctetString.fromByteArray(extensionValue)).getOctets();
    ASN1Sequence sequence = (ASN1Sequence) ASN1Sequence.fromByteArray(octets);

    Enumeration sequenceObjects = sequence.getObjects();
    while (sequenceObjects.hasMoreElements()) {
      DLSequence next = (DLSequence) sequenceObjects.nextElement();
      Object objectAt = next.getObjectAt(0);
      if (objectAt instanceof ASN1Encodable) {
        policies.add(objectAt.toString());
      }
    }
    return policies;
  }


  /**
   * Returns the internal X509 Certificate of the certificate.
   *
   * @return X509Certificate
   */
  public X509Certificate getX509Certificate() {
    return originalCert;
  }


  /**
   * Retrieves part of the issuer name (for example if set to CN it returns the Common Name part).
   *
   * @param part sets part of issuer name to return
   * @return part of issuer name
   */
  public String issuerName(Issuer part) {
    if (issuerPartMap == null) {
      loadIssuerParts();
    }
    return issuerPartMap.get(part.name());
  }

  private void loadIssuerParts() {
    String[] parts = StringUtils.split(issuerName(), ',');
    issuerPartMap = new HashMap<String, String>();
    for (int i = 0; i < parts.length; i++) {
      String[] strings = StringUtils.split(parts[i], "=");
      issuerPartMap.put(strings[0].trim(), strings[1].trim());
    }
  }

  /**
   * Reads the the whole issuer name from the X.509 certificate.
   *
   * @return issuer name
   */
  public String issuerName() {
    return originalCert.getIssuerDN().getName();
  }

  /**
   * Validates if the certificate is in a valid time slot.
   *
   * @param date sets date to compare
   * @return boolean indicating if the certificate is in a valid time slot
   */
  public boolean isValid(Date date) {
    try {
      originalCert.checkValidity(date);
    } catch (CertificateExpiredException e) {
      return false;
    } catch (CertificateNotYetValidException e) {
      return false;
    }
    return true;
  }

  /**
   * Validates if the current time is between the certificate's validity start date and expiration date.
   *
   * @return boolean indicating if the current time is between the certificate's validity start and expiration date
   */
  public boolean isValid() {
    try {
      originalCert.checkValidity();
    } catch (CertificateExpiredException e) {
      return false;
    } catch (CertificateNotYetValidException e) {
      return false;
    }
    return true;
  }

  /**
   * Returns the current certificate key usage.
   *
   * @return list of key usages
   */
  public List<KeyUsage> getKeyUsages() {
    List<KeyUsage> keyUsages = new ArrayList<KeyUsage>();
    boolean[] keyUsagesBits = originalCert.getKeyUsage();
    for (int i = 0; i < keyUsagesBits.length; i++) {
      if (keyUsagesBits[i]) {
        keyUsages.add(KeyUsage.values()[i]);
      }
    }
    return keyUsages;
  }

  /**
   * Reads serial number from X.509 certificate.
   *
   * @return serial number of the X.509 certificate
   */
  public String getSerial() {
    return Hex.toHexString(originalCert.getSerialNumber().toByteArray());
  }

  /**
   * Returns part of the subject name (for example if set to CN it returns the Common Name part).
   *
   * @param part sets part of subject name to return
   * @return subject name
   */
  public String getSubjectName(SubjectName part) {
    if (subjectNamePartMap == null) {
      loadSubjectNameParts();
    }
    return subjectNamePartMap.get(part.name());
  }

  private void loadSubjectNameParts() {
    String[] parts = getSubjectName().split(",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)");
    subjectNamePartMap = new HashMap<String, String>();
    for (int i = 0; i < parts.length; i++) {
      String[] strings = parts[i].split("=(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)");
      subjectNamePartMap.put(strings[0].trim(), strings[1].trim());
    }
  }

  /**
   * Returns the whole subject name.
   *
   * @return subject name
   */
  public String getSubjectName() {
    return originalCert.getSubjectDN().toString();
  }
}
