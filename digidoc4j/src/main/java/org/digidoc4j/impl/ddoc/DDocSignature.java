/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.ddoc;

import org.digidoc4j.Signature;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.X509Cert;
import org.digidoc4j.ddoc.CertValue;
import org.digidoc4j.ddoc.DigiDocException;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.NotYetImplementedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Signature implementation. Provides an interface for handling a signature and the
 * corresponding OCSP response properties.
 */
public class DDocSignature implements Signature {
  private static final Logger logger = LoggerFactory.getLogger(DDocSignature.class);
  private X509Cert certificate;
  private final org.digidoc4j.ddoc.Signature origin;
  private int indexInArray = 0;

  /**
   * @param signature add description
   */
  public DDocSignature(org.digidoc4j.ddoc.Signature signature) {
    this.origin = signature;
  }

  /**
   * Set certificate.
   *
   * @param cert
   */
  public void setCertificate(X509Cert cert) {
    this.certificate = cert;
  }

  @Override
  public String getCity() {
    logger.debug("getCity");
    
    String city = null;
    if (origin.getSignedProperties().getSignatureProductionPlace() != null) {
      city = origin.getSignedProperties().getSignatureProductionPlace().getCity();
    }
    
    return city == null? "" : city;
  }

  @Override
  public String getCountryName() {
    logger.debug("getCountryName");
    
    String countryName = null;
    if (origin.getSignedProperties().getSignatureProductionPlace() != null) {
      countryName = origin.getSignedProperties().getSignatureProductionPlace().getCountryName();
    }
    
    return countryName == null? "" : countryName;
  }

  @Override
  public String getId() {
    logger.debug("getId");

    String id = origin.getId();
    if(id == null) id = "";

    return id;
  }

  @Override
  public String getUniqueId() {
    return getId();
  }

  @Override
  public byte[] getOCSPNonce() {
    logger.debug("getOCSPNonce");
    try {
      return origin.getOCSPNonce();
    } catch (DigiDocException e) {
      logger.error("Failed to parse OCSP nonce: " + e.getMessage());
      throw new DigiDoc4JException(e);
    }
  }

  @Override
  public X509Cert getOCSPCertificate() {
    logger.debug("getOCSPCertificate");
    X509Certificate x509Certificate = origin.findResponderCert();
    return x509Certificate != null ? new X509Cert(x509Certificate) : null;
  }

  @Override
  public String getPostalCode() {

    String postalCode = null;
    if (origin.getSignedProperties().getSignatureProductionPlace() != null) {
      postalCode = origin.getSignedProperties().getSignatureProductionPlace().getPostalCode();
    }
    logger.debug("Postal code: " + postalCode);
    return postalCode == null? "" : postalCode;
  }

  /**
   * This method returns OCSP response creation time (Date object), it can be null.
   *
   * @return date.
   */
  @Override
  public Date getOCSPResponseCreationTime() {
    Date date = origin.getSignatureProducedAtTime();
    logger.debug("OCSP response creation time: " + date);
    return date;
  }

  @Override
  public Date getTimeStampCreationTime() {
    throw new NotYetImplementedException();
  }

  /**
   * This method returns OCSP response creation time (Date object), it can be null.
   *
   * @return date.
   */
  @Override
  public Date getTrustedSigningTime() {
    return getOCSPResponseCreationTime();
  }

  @Override
  public SignatureProfile getProfile() {
    logger.debug("Profile is LT_TM");
    return SignatureProfile.LT_TM;
  }

  @Override
  public String getSignatureMethod() {
    logger.debug("getSignatureMethod");
    String signatureMethod = origin.getSignedInfo().getSignatureMethod();
    logger.debug("Signature method: " + signatureMethod);
    return signatureMethod == null ? "" : signatureMethod;
  }

  @Override
  public List<String> getSignerRoles() {
    logger.debug("getSignerRoles");
    List<String> roles = new ArrayList<>();
    int numberOfRoles = origin.getSignedProperties().countClaimedRoles();
    for (int i = 0; i < numberOfRoles; i++) {
      roles.add(origin.getSignedProperties().getClaimedRole(i));
    }
    return roles;
  }

  @Override
  public X509Cert getSigningCertificate() {
    logger.debug("getSigningCertificate");
    return certificate;
  }

  @Override
  public Date getClaimedSigningTime() {
    logger.debug("getClaimedSigningTime");
    return origin.getSignedProperties().getSigningTime();
  }

  @Override
  public String getStateOrProvince() {
    logger.debug("getStateOrProvince");
    
    String stateOrProvince = null;
    if (origin.getSignedProperties().getSignatureProductionPlace() != null) {
      stateOrProvince = origin.getSignedProperties().getSignatureProductionPlace().getStateOrProvince();;
    }
    
    return stateOrProvince == null ? "": stateOrProvince;
  }

  @Override
  public X509Cert getTimeStampTokenCertificate() {
    throw new NotYetImplementedException();
  }

  @Override
  public ValidationResult validateSignature() {
    List validationResult = this.origin.verify(origin.getSignedDoc(), true, true);
    return new DDocSignatureValidationResult(validationResult, origin.getSignedDoc().getFormat());
  }

  /**
   * Retrieves CertValue element with the desired type
   *
   * @param type CertValue type
   * @return CertValue element or null if not found
   */
  public CertValue getCertValueOfType(int type) {
    logger.debug("type: " + type);
    return origin.getCertValueOfType(type);
  }

  @Override
  public byte[] getAdESSignature() {
    logger.debug("getAdESSignature");
    return origin.getOrigContent();
  }

  /**
   * Get index In array.
   *
   * @return integer.
   */
  public int getIndexInArray() {
    return indexInArray;
  }

  /**
   * Set index In array.
   *
   * @param indexInArray
   */
  public void setIndexInArray(int indexInArray) {
    this.indexInArray = indexInArray;
  }
}
