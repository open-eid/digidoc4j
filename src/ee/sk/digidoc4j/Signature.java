package ee.sk.digidoc4j;

import java.util.List;

/**
 * Signature interface. Provides an interface for handling a signature and the corresponding OCSP response properties
 */
public class Signature {
  public enum Validate {
    VALIDATE_TM,
    VALIDATE_POLICY,
    VALIDATE_FULL;
  }

  /**
   * @return signature production city
   */
  public String getCity() {
    return null;
  }

  /**
   * Returns signature production country
   */
  public String getCountryName() {
    return null;
  }

  /**
   * Returns signature getFileId
   */
  public String getId() {
    return null;
  }

  /**
   * Returns the signature OCSP response nonce
   */
  public byte[] getNonce() {
    return null;
  }

  /**
   * Returns the signature OCSP responder certificate
   */
  public X509Cert getOCSPCertificate() {
    return null;
  }

  /**
   * Returns the BDoc signature policy. If the container is DDoc then it returns an empty string.
   */
  public String getPolicy() {
    return null;
  }

  /**
   * Returns the signature production postal code
   */
  public String getPostalCode() {
    return null;
  }

  /**
   * Returns the signature OCSP producedAt timestamp
   */
  public String getProducedAt() {
    return null;
  }

  /**
   * Returns the signature profile
   */
  public String getProfile() {
    return null;
  }

  /**
   * Returns the signature method that was used for signing
   */
  public String getSignatureMethod() {
    return null;
  }

  /**
   * Returns the signer's roles
   */
  public List<String> getSignerRoles() {
    return null;
  }

  /**
   * Returns the signature certificate that was used for signing
   */
  public X509Cert getSigningCertificate() {
    return null;
  }

  /**
   * Returns the signature computer time that was used for signing
   */
  public X509Cert getSigningTime() {
    return null;
  }

  /**
   * Returns the BDoc signature policy uri. If the container is DDoc then it returns an empty string
   */
  public String getSignaturePolicyURI() {
    return null;
  }

  /**
   * Returns the signature production state or province
   */
  public String getStateOrProvince() {
    return null;
  }

  /**
   * Returns the signature TimeStampToken certificate
   */
  public X509Cert getTimeStampTokenCertificate() {
    return null;
  }

  /**
   * Validates signature
   *
   * @param validationType type of validation
   */
  public void validate(Validate validationType) {
  }

  /**
   * Validates signature using Validate.VALIDATE_FULL method
   */
  public void validate() {
  }


}
