package org.digidoc4j;

import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import org.digidoc4j.api.X509Cert;
import org.digidoc4j.api.exceptions.DigiDoc4JException;

import java.net.URI;
import java.util.Date;
import java.util.List;

public class BDocSignature implements SignatureInterface {
  final private SignatureParameters signatureParameters;

  public BDocSignature(byte[] signatureValue, SignatureParameters signatureParameters) {
    this.signatureParameters = signatureParameters;
  }

  @Override
  public void setCertificate(X509Cert cert) {

  }

  @Override
  public String getCity() {
    return null;
  }

  @Override
  public String getCountryName() {
    return null;
  }

  @Override
  public String getId() {
    return null;
  }

  @Override
  public byte[] getNonce() {
    return new byte[0];
  }

  @Override
  public X509Cert getOCSPCertificate() {
    return null;
  }

  @Override
  public String getPolicy() {
    return null;
  }

  @Override
  public String getPostalCode() {
    return null;
  }

  @Override
  public Date getProducedAt() {
    return null;
  }

  @Override
  public ContainerInterface.SignatureProfile getProfile() {
    return null;
  }

  @Override
  public String getSignatureMethod() {
    return null;
  }

  @Override
  public List<String> getSignerRoles() {
    return null;
  }

  @Override
  public X509Cert getSigningCertificate() {
    return null;
  }

  @Override
  public Date getSigningTime() {
    return signatureParameters.bLevel().getSigningDate();
  }

  @Override
  public URI getSignaturePolicyURI() {
    return null;
  }

  @Override
  public String getStateOrProvince() {
    return null;
  }

  @Override
  public X509Cert getTimeStampTokenCertificate() {
    return null;
  }

  @Override
  public List<DigiDoc4JException> validate(Validate validationType) {
    return null;
  }

  @Override
  public List<DigiDoc4JException> validate() {
    return null;
  }

  @Override
  public byte[] getRawSignature() {
    return new byte[0];
  }
}
