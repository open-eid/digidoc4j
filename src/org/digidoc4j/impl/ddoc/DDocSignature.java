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

import ee.sk.digidoc.CertValue;
import org.digidoc4j.Signature;
import org.digidoc4j.X509Cert;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.NotYetImplementedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.digidoc4j.SignatureProfile;

/**
 * Signature implementation. Provides an interface for handling a signature and the
 * corresponding OCSP response properties.
 */
public class DDocSignature implements Signature {
  final Logger logger = LoggerFactory.getLogger(DDocSignature.class);
  private X509Cert certificate;
  private final ee.sk.digidoc.Signature origin;
  private int indexInArray;

  /**
   * @param signature add description
   */
  public DDocSignature(ee.sk.digidoc.Signature signature) {
    logger.debug("");
    this.origin = signature;
  }

  @Override
  public void setCertificate(X509Cert cert) {
    logger.debug("");
    this.certificate = cert;
  }

  @Override
  public String getCity() {
    logger.debug("");
    return origin.getSignedProperties().getSignatureProductionPlace().getCity();
  }

  @Override
  public String getCountryName() {
    logger.debug("");
    return origin.getSignedProperties().getSignatureProductionPlace().getCountryName();
  }

  @Override
  public String getId() {
    logger.debug("");
    return origin.getId();
  }

  @Override
  public byte[] getOcspNonce() {
    logger.debug("");
    return null;
  }

  @Override
  public X509Cert getOCSPCertificate() {
    logger.debug("");
    return origin.findResponderCert() != null ? new X509Cert(origin.findResponderCert()) : null;
  }

  @Override
  @Deprecated
  public String getPolicy() {
    logger.debug("");
    return "";
  }

  @Override
  public String getPostalCode() {
    logger.debug("");
    return origin.getSignedProperties().getSignatureProductionPlace().getPostalCode();
  }

  @Override
  public Date getOCSPResponseCreationTime() {
    logger.debug("");
    return origin.getSignatureProducedAtTime();
  }

  @Override
  @Deprecated
  public Date getProducedAt() {
    return getOCSPResponseCreationTime();
  }

  @Override
  public Date getTimeStampCreationTime() {
    logger.warn("Not yet implemented");
    throw new NotYetImplementedException();
  }

  @Override
  public SignatureProfile getProfile() {
    logger.debug("Profile is LT_TM");
    return SignatureProfile.LT_TM;
  }

  @Override
  public String getSignatureMethod() {
    logger.debug("");
    String signatureMethod = origin.getSignedInfo().getSignatureMethod();
    logger.debug("Signature method: " + signatureMethod);
    return signatureMethod;
  }

  @Override
  public List<String> getSignerRoles() {
    logger.debug("");
    List<String> roles = new ArrayList<>();
    int numberOfRoles = origin.getSignedProperties().countClaimedRoles();
    for (int i = 0; i < numberOfRoles; i++) {
      roles.add(origin.getSignedProperties().getClaimedRole(i));
    }
    return roles;
  }

  @Override
  public X509Cert getSigningCertificate() {
    logger.debug("");
    return certificate;
  }

  @Override
  public Date getSigningTime() {
    logger.debug("");
    return origin.getSignedProperties().getSigningTime();
  }

  @Override
  @Deprecated
  public URI getSignaturePolicyURI() {
    logger.debug("");
    return null;
  }

  @Override
  public String getStateOrProvince() {
    logger.debug("");
    return origin.getSignedProperties().getSignatureProductionPlace().getStateOrProvince();
  }

  @Override
  public X509Cert getTimeStampTokenCertificate() {
    logger.warn("Not yet implemented");
    throw new NotYetImplementedException();
  }

  @Override
  public List<DigiDoc4JException> validate(Validate validationType) {
    logger.debug("");
    return validate();
  }

  @Override
  public List<DigiDoc4JException> validate() {
    logger.debug("");
    List<DigiDoc4JException> validationErrors = new ArrayList<>();
    ArrayList validationResult = origin.verify(origin.getSignedDoc(), true, true);
    for (Object exception : validationResult) {
      String errorMessage = exception.toString();
      logger.info(errorMessage);
      validationErrors.add(new DigiDoc4JException(errorMessage));
    }
    return validationErrors;
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
  public byte[] getRawSignature() {
    logger.debug("");
    return origin.getOrigContent();
  }

  public int getIndexInArray() {
    return indexInArray;
  }

  public void setIndexInArray(int indexInArray) {
    this.indexInArray = indexInArray;
  }
}
