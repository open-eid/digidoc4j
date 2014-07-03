package org.digidoc4j.api;

import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import org.digidoc4j.BDocSignature;
import org.digidoc4j.DDocSignature;
import org.digidoc4j.SignatureInterface;
import org.digidoc4j.api.exceptions.DigiDoc4JException;

import java.net.URI;
import java.util.Date;
import java.util.List;

import static org.digidoc4j.ContainerInterface.SignatureProfile;

/**
 * Signature implementation. Provides an interface for handling a signature and the corresponding OCSP response properties.
 */
public class Signature implements SignatureInterface {
  private final SignatureInterface signature;

  public Signature(ee.sk.digidoc.Signature signature) {
    this.signature = new DDocSignature(signature);
  }

  public Signature(byte[] signatureValue, SignatureParameters signatureParameters) {
    signature = new BDocSignature(signatureValue, signatureParameters);
  }

  @Override
  public void setCertificate(X509Cert cert) {
    signature.setCertificate(cert);
  }

  @Override
  public String getCity() {
    return signature.getCity();
  }

  @Override
  public String getCountryName() {
    return signature.getCountryName();
  }

  @Override
  public String getId() {
    return signature.getId();
  }

  @Override
  public byte[] getNonce() {
    return signature.getNonce();
  }

  @Override
  public X509Cert getOCSPCertificate() {
    return signature.getOCSPCertificate();
  }

  @Override
  public String getPolicy() {
    return signature.getPolicy();
  }

  @Override
  public String getPostalCode() {
    return signature.getPostalCode();
  }

  @Override
  public Date getProducedAt() {
    return signature.getProducedAt();
  }

  @Override
  public SignatureProfile getProfile() {
    return signature.getProfile();
  }

  @Override
  public String getSignatureMethod() {
    return signature.getSignatureMethod();
  }

  @Override
  public List<String> getSignerRoles() {
    return signature.getSignerRoles();
  }

  @Override
  public X509Cert getSigningCertificate() {
    return signature.getSigningCertificate();
  }

  @Override
  public Date getSigningTime() {
    return signature.getSigningTime();
  }

  @Override
  public URI getSignaturePolicyURI() {
    return signature.getSignaturePolicyURI();
  }

  @Override
  public String getStateOrProvince() {
    return signature.getStateOrProvince();
  }

  @Override
  public X509Cert getTimeStampTokenCertificate() {
    return signature.getTimeStampTokenCertificate();
  }

  @Override
  public List<DigiDoc4JException> validate(Validate validationType) {
    return signature.validate(validationType);
  }

  @Override
  public List<DigiDoc4JException> validate() {
    return signature.validate();
  }

  @Override
  public byte[] getRawSignature() {
    return signature.getRawSignature();
  }
}
