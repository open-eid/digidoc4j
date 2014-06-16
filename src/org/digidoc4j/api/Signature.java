package org.digidoc4j.api;

import java.net.URI;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.digidoc4j.SignatureInterface;
import org.digidoc4j.api.exceptions.DigiDoc4JException;
import org.digidoc4j.api.exceptions.NotYetImplementedException;
import org.digidoc4j.utils.SignerInformation;

import static org.digidoc4j.ContainerInterface.SignatureProfile;

/**
 * Signature implementation. Provides an interface for handling a signature and the corresponding OCSP response properties.
 */
public class Signature implements SignatureInterface {
  private byte[] signatureValue;
  private SignerInformation signerInformation;
  private Date signingTime;
  private List<String> signerRoles;
  private X509Cert certificate;
  private ee.sk.digidoc.Signature jDigiDocOrigin;

  /**
   * Signature default constructor
   *
   * @param signatureValue aa
   * @param signer         ss
   */
  public Signature(byte[] signatureValue, Signer signer) {
    this.signatureValue = signatureValue;
    this.signerInformation = signer.getSignerInformation();
    this.signerRoles = signer.getSignerRoles();
    this.certificate = signer.getCertificate();
  }

  public Signature(byte[] signatureValue) {
    this.signatureValue = signatureValue;
  }

  public void setSigningTime(Date signingTime) {
    this.signingTime = signingTime;
  }

  public void setSignerRoles(List<String> roles) {
    signerRoles = roles;
  }

  public void setSignerInformation(SignerInformation signerInformation) {
    this.signerInformation = signerInformation;
  }

  public void setCertificate(X509Cert cert) {
    this.certificate = cert;
  }

  public void setJDigiDocOrigin(ee.sk.digidoc.Signature jDigiDocOrigin) {
    this.jDigiDocOrigin = jDigiDocOrigin;
  }

  /**
   * Returns the signature production city.
   *
   * @return production city
   */
  public String getCity() {
    return signerInformation.getCity();
  }

  /**
   * Returns the signature production country.
   *
   * @return production country
   */
  public String getCountryName() {
    return signerInformation.getCountry();
  }

  /**
   * Returns the signature id.
   *
   * @return id
   */
  public String getId() {
    return jDigiDocOrigin.getId();
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
    return new X509Cert(jDigiDocOrigin.findResponderCert());
  }

  /**
   * Returns the BDoc signature policy. If the container is DDoc then it returns an empty string.
   *
   * @return signature policy
   */
  public String getPolicy() {
    return "";
  }

  /**
   * Returns the signature production postal code.
   *
   * @return postal code
   */
  public String getPostalCode() {
    return signerInformation.getPostalCode();
  }

  /**
   * Returns the signature OCSP producedAt timestamp if exists. Otherwise returns null
   *
   * @return producedAt timestamp
   */
  public Date getProducedAt() {
    return jDigiDocOrigin.getSignatureProducedAtTime();
  }

  /**
   * Returns the signature profile.
   *
   * @return profile
   */
  public SignatureProfile getProfile() {
    return "TM".equals(jDigiDocOrigin.getProfile()) ? SignatureProfile.TM : SignatureProfile.TS;
  }

  /**
   * Returns the signature method that was used for signing.
   *
   * @return signature method
   */
  public String getSignatureMethod() {
    return jDigiDocOrigin.getSignedInfo().getSignatureMethod();
  }

  /**
   * Returns the signer's roles.
   *
   * @return signer roles
   */
  public List<String> getSignerRoles() {
    return signerRoles;
  }

  /**
   * Returns the signature certificate that was used for signing.
   *
   * @return signature certificate
   */
  public X509Cert getSigningCertificate() {
    return certificate;
  }

  /**
   * Returns the computer's time of signing.
   *
   * @return signing time
   */
  public Date getSigningTime() {
    return signingTime;
  }

  /**
   * Returns the BDoc signature policy uri. If the container is DDoc then it returns null.
   *
   * @return signature policy uri
   */
  public URI getSignaturePolicyURI() {
    return null;
  }

  /**
   * Returns the signature production state or province.
   *
   * @return production state or province
   */
  public String getStateOrProvince() {
    return signerInformation.getStateOrProvince();
  }

  /**
   * Returns the signature TimeStampToken certificate.
   *
   * @return TimeStampToken certificate
   */
  public X509Cert getTimeStampTokenCertificate() {
    throw new NotYetImplementedException();
  }

  /**
   * Validates the signature. In case of DDOC makes full validation.
   *
   * @param validationType type of validation
   */
  public List<DigiDoc4JException> validate(Validate validationType) {
    return validate();
  }

  /**
   * Validates the signature using Validate.VALIDATE_FULL method.
   *
   * @return returns list of validation exceptions. NB! legacy it can be changed!!!
   */
  public List<DigiDoc4JException> validate() {
    List<DigiDoc4JException> validationErrors = new ArrayList<DigiDoc4JException>();
    ArrayList validationResult = jDigiDocOrigin.verify(jDigiDocOrigin.getSignedDoc(), true, true);
    for (Object exception : validationResult) {
      validationErrors.add(new DigiDoc4JException((Exception)exception));
    }
    return validationErrors;
  }

  /**
   * Returns raw signature
   *
   * @return signature value as byte array
   */
  public byte[] getRawSignature() {
    if (jDigiDocOrigin == null)
      return signatureValue;
    return
      jDigiDocOrigin.getOrigContent();
  }
}
