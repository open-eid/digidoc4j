package ee.sk.digidoc4j;

import ee.sk.digidoc4j.utils.SignerInformation;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;

import java.util.List;

/**
 * Signature interface. Provides an interface for handling a signature and the corresponding OCSP response properties.
 */
public class Signature {
  private SignerInformation signerInformation;
  private byte[] signatureValue;
  private SignatureParameters signatureParameters;

  /**
   * Signature default constructor
   */
  public Signature(SignerInformation signerInformation, byte[] signatureValue, SignatureParameters signatureParameters) {
    this.signerInformation = signerInformation;
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
    return signerInformation.city;
  }

  /**
   * Returns the signature production country.
   *
   * @return production country
   */
  public String getCountryName() {
    return null;
  }

  /**
   * Returns the signature id.
   *
   * @return id
   */
  public String getId() {
    return null;
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
    return null;
  }

  /**
   * Returns the signature OCSP producedAt timestamp.
   *
   * @return producedAt timestamp
   */
  public String getProducedAt() {
    return null;
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
   * @return signer role
   */
  public List<String> getSignerRoles() {
    return null;
  }

  /**
   * Returns the signature certificate that was used for signing.
   *
   * @return signature certificate
   */
  public X509Cert getSigningCertificate() {
    return null;
  }

  /**
   * Returns the computer's time of signing.
   *
   * @return signing time
   */
  public X509Cert getSigningTime() {
    return null;
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
    return null;
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


}
