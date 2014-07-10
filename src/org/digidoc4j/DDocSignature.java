package org.digidoc4j;

import org.digidoc4j.api.X509Cert;
import org.digidoc4j.api.exceptions.DigiDoc4JException;
import org.digidoc4j.api.exceptions.NotYetImplementedException;

import java.net.URI;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.digidoc4j.ContainerInterface.SignatureProfile;

/**
 * Signature implementation. Provides an interface for handling a signature and the corresponding OCSP response properties.
 */
public class DDocSignature implements SignatureInterface {
  final private ee.sk.digidoc.Signature origin;

  public DDocSignature(ee.sk.digidoc.Signature signature) {
    this.origin = signature;
  }

//  @Override
//  public void setCertificate(X509Cert cert) {
//    this.certificate = cert;
//  }

  @Override
  public String getCity() {
    return origin.getSignedProperties().getSignatureProductionPlace().getCity();
  }

  @Override
  public String getCountryName() {
    return origin.getSignedProperties().getSignatureProductionPlace().getCountryName();
  }

  @Override
  public String getId() {
    return origin.getId();
  }

  @Override
  public byte[] getNonce() {
    return null;
  }

  @Override
  public X509Cert getOCSPCertificate() {
    return new X509Cert(origin.findResponderCert());
  }

  @Override
  public String getPolicy() {
    return "";
  }

  @Override
  public String getPostalCode() {
    return origin.getSignedProperties().getSignatureProductionPlace().getPostalCode();
  }

  @Override
  public Date getProducedAt() {
    return origin.getSignatureProducedAtTime();
  }

  @Override
  public SignatureProfile getProfile() {
    return "TM".equals(origin.getProfile()) ? SignatureProfile.TM : SignatureProfile.TS;
  }

  @Override
  public String getSignatureMethod() {
    return origin.getSignedInfo().getSignatureMethod();
  }

  @Override
  public List<String> getSignerRoles() {
    List<String> roles = new ArrayList<String>();
    int numberOfRoles = origin.getSignedProperties().countClaimedRoles();
    for (int i = 0; i < numberOfRoles; i++) {
      roles.add(origin.getSignedProperties().getClaimedRole(i));
    }
    return roles;
  }

  @Override
  public X509Cert getSigningCertificate() {
    return new X509Cert(origin.getLastCertValue().getCert());
  }

  @Override
  public Date getSigningTime() {
    return origin.getSignedProperties().getSigningTime();
  }

  @Override
  public URI getSignaturePolicyURI() {
    return null;
  }

  @Override
  public String getStateOrProvince() {
    return origin.getSignedProperties().getSignatureProductionPlace().getStateOrProvince();
  }

  @Override
  public X509Cert getTimeStampTokenCertificate() {
    throw new NotYetImplementedException();
  }

  @Override
  public List<DigiDoc4JException> validate(Validate validationType) {
    return validate();
  }

  @Override
  public List<DigiDoc4JException> validate() {
    List<DigiDoc4JException> validationErrors = new ArrayList<DigiDoc4JException>();
    ArrayList validationResult = origin.verify(origin.getSignedDoc(), true, true);
    for (Object exception : validationResult) {
      validationErrors.add(new DigiDoc4JException((Exception) exception));
    }
    return validationErrors;
  }

  @Override
  public byte[] getRawSignature() {
    return origin.getOrigContent();
  }
}
