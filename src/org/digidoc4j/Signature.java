package org.digidoc4j;

import eu.europa.ec.markt.dss.parameter.SignatureParameters;

import java.util.Date;
import java.util.List;

import org.digidoc4j.exceptions.NotYetImplementedException;

/**
 * Signature interface. Provides an interface for handling a signature and the corresponding OCSP response properties.
 */
public class Signature {
  private byte[] signatureValue;
  private SignatureParameters signatureParameters;

  /**
   * Signature default constructor
   *
   * @param signatureValue      aa
   * @param signatureParameters ss
   */
  public Signature(byte[] signatureValue, SignatureParameters signatureParameters) {
    this.signatureValue = signatureValue;
    this.signatureParameters = signatureParameters;
  }

  /**
   * Signature validation types.
   */
  public enum Validate {
    VALIDATE_TM,
    VALIDATE_POLICY,
    VALIDATE_FULL;
  }

  /**
   * Returns the signature production city.
   *
   * @return production city
   */
  public String getCity() {
    return signatureParameters.bLevel().getSignerLocation().getCity();
  }

  /**
   * Returns the signature production country.
   *
   * @return production country
   */
  public String getCountryName() {
    return signatureParameters.bLevel().getSignerLocation().getCountry();
  }

  /**
   * Returns the signature id.
   *
   * @return id
   * @throws Exception when method is not implemented
   */
  public String getId() throws Exception {
    throw new NotYetImplementedException();
  }

  /**
   * Returns the signature OCSP response nonce.
   *
   * @return OCSP response nonce
   */
  public byte[] getNonce() {
    return null;
  }

  /**
   * Returns the signature OCSP responder certificate.
   *
   * @return OCSP responder certificate
   */
  public X509Cert getOCSPCertificate() {
    return null;
  }

  /**
   * Returns the BDoc signature policy. If the container is DDoc then it returns an empty string.
   *
   * @return signature policy
   */
  public String getPolicy() {
    return null;
  }

  /**
   * Returns the signature production postal code.
   *
   * @return postal code
   */
  public String getPostalCode() {
    return signatureParameters.bLevel().getSignerLocation().getPostalCode();
  }

  /**
   * Returns the signature OCSP producedAt timestamp.
   *
   * @return producedAt timestamp
   * @throws Exception when not yet implemented
   */
  public Date getProducedAt() throws Exception {
    throw new NotYetImplementedException();
  }

  /**
   * Returns the signature profile.
   *
   * @return profile
   */
  public String getProfile() {
    return null;
  }

  /**
   * Returns the signature method that was used for signing.
   *
   * @return signature method
   */
  public String getSignatureMethod() {
    return null;
  }

  /**
   * Returns the signer's roles.
   *
   * @return signer roles
   */
  public List<String> getSignerRoles() {
    return signatureParameters.bLevel().getClaimedSignerRoles();
  }

  /**
   * Returns the signature certificate that was used for signing.
   *
   * @return signature certificate
   */
  public X509Cert getSigningCertificate() {
    return new X509Cert(signatureParameters.getSigningCertificate());
  }

  /**
   * Returns the computer's time of signing.
   *
   * @return signing time
   */
  public Date getSigningTime() {
    return signatureParameters.bLevel().getSigningDate();
  }

  /**
   * Returns the BDoc signature policy uri. If the container is DDoc then it returns an empty string.
   *
   * @return signature policy uri
   */
  public String getSignaturePolicyURI() {
    return null;
  }

  /**
   * Returns the signature production state or province.
   *
   * @return production state or province
   */
  public String getStateOrProvince() {
    return signatureParameters.bLevel().getSignerLocation().getStateOrProvince();
  }

  /**
   * Returns the signature TimeStampToken certificate.
   *
   * @return TimeStampToken certificate
   */
  public X509Cert getTimeStampTokenCertificate() {
    return null;
  }

  /**
   * Validates the signature.
   *
   * @param validationType type of validation
   */
  public void validate(Validate validationType) {
  }

  /**
   * Validates the signature using Validate.VALIDATE_FULL method.
   */
  public void validate() {
  }

  /**
   * Returns raw signature
   *
   * @return signature value as byte array
   */
  public byte[] getRawSignature() {
    return signatureValue;
  }
}
