package org.digidoc4j;

import eu.europa.ec.markt.dss.parameter.BLevelParameters;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import org.digidoc4j.api.X509Cert;
import org.digidoc4j.api.exceptions.DigiDoc4JException;
import sun.security.x509.X509CertImpl;

import java.net.URI;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.List;

public class BDocSignature implements SignatureInterface {
  final private SignatureParameters signatureParameters;
  private final byte[] signatureBytes;
  private BLevelParameters.SignerLocation signerLocation;

  public BDocSignature(byte[] signatureValue, SignatureParameters signatureParameters) {
    signatureBytes = signatureValue;
    this.signatureParameters = signatureParameters;
    signerLocation = signatureParameters.bLevel().getSignerLocation();
  }

  @Override
  public void setCertificate(X509Cert cert) {

  }

  @Override
  public String getCity() {
    return signerLocation.getCity();
  }

  @Override
  public String getCountryName() {
    return signerLocation.getCountry();
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
    return signerLocation.getPostalCode();
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
    return signatureParameters.bLevel().getClaimedSignerRoles();
  }

  @Override
  public X509Cert getSigningCertificate() {
    try {
      return new X509Cert(new X509CertImpl(signatureBytes));
    } catch (CertificateException e) {
      throw new DigiDoc4JException(e);
    }
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
    return signerLocation.getStateOrProvince();
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
    return signatureBytes;
  }
}
