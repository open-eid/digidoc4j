package org.digidoc4j;

import java.util.Date;
import java.util.List;

import org.digidoc4j.api.X509Cert;

/**
 * Signature interface. Provides an interface for handling a signature and the corresponding OCSP response properties.
 */
public interface SignatureInterface {

  public void setCertificate(X509Cert cert);

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
  public String getCity();

  /**
   * Returns the signature production country.
   *
   * @return production country
   */
  public String getCountryName();

  /**
   * Returns the signature id.
   *
   * @return id
   */
  public String getId();

  /**
   * Returns the signature OCSP response nonce.
   *
   * @return OCSP response nonce
   */
  public byte[] getNonce();

  /**
   * Returns the signature OCSP responder certificate.
   *
   * @return OCSP responder certificate
   */
  public X509Cert getOCSPCertificate();

  /**
   * Returns the BDoc signature policy. If the container is DDoc then it returns an empty string.
   *
   * @return signature policy
   */
  public String getPolicy();

  /**
   * Returns the signature production postal code.
   *
   * @return postal code
   */
  public String getPostalCode();

  /**
   * Returns the signature OCSP producedAt timestamp.
   *
   * @return producedAt timestamp
   */
  public Date getProducedAt();

  /**
   * Returns the signature profile.
   *
   * @return profile
   */
  public ContainerInterface.SignatureProfile getProfile();

  /**
   * Returns the signature method that was used for signing.
   *
   * @return signature method
   */
  public String getSignatureMethod();

  /**
   * Returns the signer's roles.
   *
   * @return signer roles
   */
  public List<String> getSignerRoles();

  /**
   * Returns the signature certificate that was used for signing.
   *
   * @return signature certificate
   */
  public X509Cert getSigningCertificate();

  /**
   * Returns the computer's time of signing.
   *
   * @return signing time
   */
  public Date getSigningTime();

  /**
   * Returns the BDoc signature policy uri. If the container is DDoc then it returns an empty string.
   *
   * @return signature policy uri
   */
  public java.net.URI getSignaturePolicyURI();

  /**
   * Returns the signature production state or province.
   *
   * @return production state or province
   */
  public String getStateOrProvince();

  /**
   * Returns the signature TimeStampToken certificate.
   *
   * @return TimeStampToken certificate
   */
  public X509Cert getTimeStampTokenCertificate();

  /**
   * Validates the signature.
   *
   * @param validationType type of validation
   */
  public List<org.digidoc4j.api.exceptions.DigiDoc4JException> validate(Validate validationType);

  /**
   * Validates the signature using Validate.VALIDATE_FULL method.
   */
  public List<org.digidoc4j.api.exceptions.DigiDoc4JException> validate();

  /**
   * Returns raw signature
   *
   * @return signature value as byte array
   */
  public byte[] getRawSignature();
}
