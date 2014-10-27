package org.digidoc4j.impl;

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

import static org.digidoc4j.Container.SignatureProfile;

/**
 * Signature implementation. Provides an interface for handling a signature and the
 * corresponding OCSP response properties.
 */
public class DDocSignature extends Signature {
  final Logger logger = LoggerFactory.getLogger(DDocSignature.class);
  private X509Cert certificate;
  private final ee.sk.digidoc.Signature origin;

  /**
   * @param signature add description
   */
  public DDocSignature(ee.sk.digidoc.Signature signature) {
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
  public byte[] getNonce() {
    logger.debug("");
    return null;
  }

  @Override
  public X509Cert getOCSPCertificate() {
    logger.debug("");
    return origin.findResponderCert() != null ? new X509Cert(origin.findResponderCert()) : null;
  }

  @Override
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
  public Date getProducedAt() {
    logger.debug("");
    return origin.getSignatureProducedAtTime();
  }

  @Override
  public SignatureProfile getProfile() {
    logger.debug("Profile is TM");
    return SignatureProfile.TM;
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
    List<String> roles = new ArrayList<String>();
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
    List<DigiDoc4JException> validationErrors = new ArrayList<DigiDoc4JException>();
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
}
