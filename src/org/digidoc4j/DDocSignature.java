package org.digidoc4j;

import org.digidoc4j.api.Signature;
import org.digidoc4j.api.X509Cert;
import org.digidoc4j.api.exceptions.DigiDoc4JException;
import org.digidoc4j.api.exceptions.NotYetImplementedException;

import java.net.URI;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.digidoc4j.api.Container.SignatureProfile;

/**
 * Signature implementation. Provides an interface for handling a signature and the corresponding OCSP response properties.
 */
public class DDocSignature extends Signature {
  private X509Cert certificate;
  final private ee.sk.digidoc.Signature origin;

  public DDocSignature(ee.sk.digidoc.Signature signature) {
    this.origin = signature;
  }

  public void setCertificate(X509Cert cert) {
    this.certificate = cert;
  }

  public String getCity() {
    return origin.getSignedProperties().getSignatureProductionPlace().getCity();
  }

  public String getCountryName() {
    return origin.getSignedProperties().getSignatureProductionPlace().getCountryName();
  }

  public String getId() {
    return origin.getId();
  }

  public byte[] getNonce() {
    return null;
  }

  public X509Cert getOCSPCertificate() {
    return new X509Cert(origin.findResponderCert());
  }

  public String getPolicy() {
    return "";
  }

  public String getPostalCode() {
    return origin.getSignedProperties().getSignatureProductionPlace().getPostalCode();
  }

  public Date getProducedAt() {
    return origin.getSignatureProducedAtTime();
  }

  public SignatureProfile getProfile() {
    return "TM".equals(origin.getProfile()) ? SignatureProfile.TM : SignatureProfile.TS;
  }

  public String getSignatureMethod() {
    return origin.getSignedInfo().getSignatureMethod();
  }

  public List<String> getSignerRoles() {
    List<String> roles = new ArrayList<String>();
    int numberOfRoles = origin.getSignedProperties().countClaimedRoles();
    for (int i = 0; i < numberOfRoles; i++) {
      roles.add(origin.getSignedProperties().getClaimedRole(i));
    }
    return roles;
  }

  public X509Cert getSigningCertificate() {
    return certificate;
  }

  public Date getSigningTime() {
    return origin.getSignedProperties().getSigningTime();
  }

  public URI getSignaturePolicyURI() {
    return null;
  }

  public String getStateOrProvince() {
    return origin.getSignedProperties().getSignatureProductionPlace().getStateOrProvince();
  }

  public X509Cert getTimeStampTokenCertificate() {
    throw new NotYetImplementedException();
  }

  public List<DigiDoc4JException> validate(Validate validationType) {
    return validate();
  }

  public List<DigiDoc4JException> validate() {
    List<DigiDoc4JException> validationErrors = new ArrayList<DigiDoc4JException>();
    ArrayList validationResult = origin.verify(origin.getSignedDoc(), true, true);
    for (Object exception : validationResult) {
      validationErrors.add(new DigiDoc4JException((Exception) exception));
    }
    return validationErrors;
  }

  public byte[] getRawSignature() {
    return origin.getOrigContent();
  }
}
