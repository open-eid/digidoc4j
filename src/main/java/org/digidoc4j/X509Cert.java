/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.Serializable;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Wrapper for java.security.cert.X509Certificate object.
 */
public class X509Cert implements Serializable {
  private static final Logger logger = LoggerFactory.getLogger(X509Cert.class);
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
    DECIPHER_ONLY
  }

  /**
   * Issuer parts.
   */
  public enum Issuer {
    EMAILADDRESS,
    C,
    O,
    CN
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
    C
  }


  /**
   * Creates a copy of the X509Certificate.
   *
   * @param cert X509 certificate to be wrapped
   */
  public X509Cert(X509Certificate cert) {
    logger.debug("");
    originalCert = cert;
  }

  /**
   * Creates an X509 certificate from a path.
   *
   * @param path X509 certificate path
   * @throws Exception throws an exception if the X509 certificate parsing fails
   */
  X509Cert(String path) {
    try {
      CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
      try (FileInputStream inStream = new FileInputStream(new File(path))) {
        this.originalCert = (X509Certificate) certificateFactory.generateCertificate(inStream);
      }
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Returns current certificate policies or null if no policies was found.
   *
   * @return list of policies
   * @throws IOException when policy parsing fails
   */
  public List<String> getCertificatePolicies() throws IOException {
    logger.debug("");
    byte[] extensionValue = originalCert.getExtensionValue("2.5.29.32");
    List<String> policies = new ArrayList<>();

    byte[] octets = ((DEROctetString) DEROctetString.fromByteArray(extensionValue)).getOctets();
    ASN1Sequence sequence = (ASN1Sequence) ASN1Sequence.fromByteArray(octets);

    Enumeration sequenceObjects = sequence.getObjects();
    while (sequenceObjects.hasMoreElements()) {
      DLSequence next = (DLSequence) sequenceObjects.nextElement();
      Object objectAt = next.getObjectAt(0);
      if (objectAt != null) {
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
    logger.debug("");
    return originalCert;
  }


  /**
   * Retrieves part of the issuer name (for example if set to CN it returns the Common Name part).
   *
   * @param part sets part of issuer name to return
   * @return part of issuer name
   */
  public String issuerName(Issuer part) {
    logger.debug("Part: " + part);
    if (issuerPartMap == null) {
      loadIssuerParts();
    }
    String issuerName = issuerPartMap.get(part.name());
    logger.debug("Issuer name: " + issuerName);
    return issuerName;
  }

  private void loadIssuerParts() {
    logger.debug("");
    String[] parts = StringUtils.split(issuerName(), ',');
    issuerPartMap = new HashMap<>();
    for (String part : parts) {
      String[] strings = StringUtils.split(part, "=");
      String key = strings[0].trim();
      String value = strings[1].trim();
      issuerPartMap.put(key, value);
      logger.debug("Subject name part key: " + key + " value: " + value);
    }
  }

  /**
   * Reads the the whole issuer name from the X.509 certificate.
   *
   * @return issuer name
   */
  public String issuerName() {
    logger.debug("");
    String name = originalCert.getIssuerDN().getName();
    logger.debug("Issuer name: " + name);
    return name;
  }

  /**
   * Validates if the certificate is in a valid time slot.
   *
   * @param date sets date to compare
   * @return boolean indicating if the certificate is in a valid time slot
   */
  public boolean isValid(Date date) {
    logger.debug("Date: " + date);
    try {
      originalCert.checkValidity(date);
    } catch (CertificateExpiredException e) {
      logger.debug("Date " + date + " is not valid");
      return false;
    } catch (CertificateNotYetValidException e) {
      logger.debug("Date " + date + " is not valid");
      return false;
    }
    logger.debug("Date " + date + " is valid");
    return true;
  }

  /**
   * Validates if the current time is between the certificate's validity start date and expiration date.
   *
   * @return boolean indicating if the current time is between the certificate's validity start and expiration date
   */
  public boolean isValid() {
    logger.debug("");
    return (isValid(new Date()));
  }

  /**
   * Returns the current certificate key usage.
   *
   * @return list of key usages
   */
  public List<KeyUsage> getKeyUsages() {
    logger.debug("");
    List<KeyUsage> keyUsages = new ArrayList<>();
    boolean[] keyUsagesBits = originalCert.getKeyUsage();
    for (int i = 0; i < keyUsagesBits.length; i++) {
      if (keyUsagesBits[i]) {
        keyUsages.add(KeyUsage.values()[i]);
      }
    }

    logger.debug("Returning " + keyUsages.size() + "key usages:");
    for (KeyUsage keyUsage : keyUsages) {
      logger.debug("\t" + keyUsage.toString());
    }

    return keyUsages;
  }

  /**
   * Reads serial number from X.509 certificate.
   *
   * @return serial number of the X.509 certificate
   */
  public String getSerial() {
    logger.debug("");
    String serial = Hex.toHexString(originalCert.getSerialNumber().toByteArray());
    logger.debug("Serial number: " + serial);
    return serial;
  }

  /**
   * Returns part of the subject name (for example if set to CN it returns the Common Name part).
   *
   * @param part sets part of subject name to return
   * @return subject name
   */
  public String getSubjectName(SubjectName part) {
    logger.debug("Part: " + part);
    if (subjectNamePartMap == null) {
      loadSubjectNameParts();
    }
    String subjectName = subjectNamePartMap.get(part.name());
    logger.debug("Subject name: " + subjectName);
    return subjectName;
  }

  private void loadSubjectNameParts() {
    logger.debug("");
    String[] parts = getSubjectName().split(",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)");
    subjectNamePartMap = new HashMap<>();
    for (String part : parts) {
      String[] strings = part.split("=(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)");
      String key = strings[0].trim();
      String value = strings[1].trim();
      subjectNamePartMap.put(key, value);
      logger.debug("Subject name part key: " + key + " value: " + value);
    }
  }

  /**
   * Returns the whole subject name.
   *
   * @return subject name
   */
  public String getSubjectName() {
    logger.debug("");
    String subjectName = originalCert.getSubjectX500Principal().toString();
    logger.debug("Subject name: " + subjectName);
    return subjectName;
  }
}
