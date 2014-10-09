package org.digidoc4j;

import org.digidoc4j.exceptions.DigiDoc4JException;

import java.util.Date;
import java.util.List;

/**
 * Signature interface. Provides an interface for handling a signature and the corresponding OCSP response properties.
 */
public abstract class Signature {

  /**
   * Sets signer certificate
   * For a BDOC Signature it throws a NotYetImplementedException.
   *
   * @param cert signers certificate
   */
  public abstract void setCertificate(X509Cert cert);

  /**
   * Signature validation types.
   */
  public enum Validate {
    VALIDATE_TM,
    VALIDATE_POLICY,
    VALIDATE_FULL
  }

  /**
   * Returns the signature production city.
   *
   * @return production city
   */
  public abstract String getCity();

  /**
   * Returns the signature production country.
   *
   * @return production country
   */
  public abstract String getCountryName();

  /**
   * Returns the signature id.
   *
   * @return id
   */
  public abstract String getId();

  /**
   * Returns the signature OCSP response nonce.
   *
   * For a BDOC Signature it throws a NotYetImplementedException.
   *
   * @return OCSP response nonce
   */
  public abstract byte[] getNonce();

  /**
   * Returns the signature OCSP responder certificate.
   *
   * @return OCSP responder certificate
   */
  public abstract X509Cert getOCSPCertificate();

  /**
   * If the container is DDOC then it returns an empty string.
   *
   * For a BDOC Signature it throws a NotYetImplementedException.
   *
   * @return signature policy
   */
  public abstract String getPolicy();

  /**
   * Returns the signature production postal code.
   *
   * @return postal code
   */
  public abstract String getPostalCode();

  /**
   * Returns the signature OCSP producedAt timestamp.
   *
   * @return producedAt timestamp
   */
  public abstract Date getProducedAt();

  /**
   * Returns the signature profile.
   *
   * @return profile
   */
  public abstract Container.SignatureProfile getProfile();

  /**
   * Returns the signature method that was used for signing.
   *
   * @return signature method
   */
  public abstract String getSignatureMethod();

  /**
   * Returns the signer's roles.
   *
   * @return signer roles
   */
  public abstract List<String> getSignerRoles();

  /**
   * Returns the signature certificate that was used for signing.
   *
   * @return signature certificate
   */
  public abstract X509Cert getSigningCertificate();

  /**
   * Returns the computer's time of signing.
   *
   * @return signing time
   */
  public abstract Date getSigningTime();

  /**
   * If the container is DDoc then it returns an empty string.
   * For a BDOC Signature it throws a NotYetImplementedException.
   *
   * @return signature policy uri
   */
  public abstract java.net.URI getSignaturePolicyURI();

  /**
   * Returns the signature production state or province.
   *
   * @return production state or province
   */
  public abstract String getStateOrProvince();

  /**
   * Returns the signature TimeStampToken certificate.
   * For a DDOC Signature it throws a NotYetImplementedException.
   *
   * @return TimeStampToken certificate
   */
  public abstract X509Cert getTimeStampTokenCertificate();

  /**
   * Validates the signature.
   *
   * @param validationType type of validation
   * @return list of Digidoc4JExceptions
   */
  public abstract List<DigiDoc4JException> validate(Validate validationType);

  /**
   * Validates the signature using Validate.VALIDATE_FULL method.
   *
   * @return list of Digidoc4JExceptions
   */
  public abstract List<DigiDoc4JException> validate();

  /**
   * Returns raw signature
   *
   * @return signature value as byte array
   */
  public abstract byte[] getRawSignature();
}
