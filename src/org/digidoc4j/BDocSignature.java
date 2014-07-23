package org.digidoc4j;

import eu.europa.ec.markt.dss.validation102853.CertificateToken;
import eu.europa.ec.markt.dss.validation102853.bean.SignatureProductionPlace;
import eu.europa.ec.markt.dss.validation102853.xades.XAdESSignature;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.ocsp.RespID;
import org.digidoc4j.api.Signature;
import org.digidoc4j.api.X509Cert;
import org.digidoc4j.api.exceptions.CertificateNotFoundException;
import org.digidoc4j.api.exceptions.DigiDoc4JException;
import org.digidoc4j.api.exceptions.NotYetImplementedException;

import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import static org.digidoc4j.api.Container.SignatureProfile;

public class BDocSignature extends Signature {
  private XAdESSignature origin;
  private SignatureProductionPlace signerLocation;
  private List<DigiDoc4JException> validationErrors = new ArrayList<DigiDoc4JException>();

  public BDocSignature(XAdESSignature signature) {
    origin = signature;
    signerLocation = signature.getSignatureProductionPlace();
  }

  public BDocSignature(XAdESSignature signature, List<DigiDoc4JException> validationErrors) {
    origin = signature;
    signerLocation = signature.getSignatureProductionPlace();
    this.validationErrors = validationErrors;
  }

  public void setCertificate(X509Cert cert) {
    throw new NotYetImplementedException();
  }

  public String getCity() {
    return signerLocation.getCity();
  }

  public String getCountryName() {
    return signerLocation.getCountryName();
  }

  public String getId() {
    return origin.getId();
  }

  public byte[] getNonce() {
    throw new NotYetImplementedException();
  }

  public X509Cert getOCSPCertificate() {
    String ocspCN = getOCSPCommonName();
    for (CertificateToken cert : origin.getCertPool().getCertificateTokens()) {
      String value = getCN(new X500Name(cert.getSubjectX500Principal().getName()));
      if (value.equals(ocspCN))
        return new X509Cert(cert.getCertificate());
    }
    throw new CertificateNotFoundException("Certificate for " + ocspCN + " not found in TSL");
  }

  private String getOCSPCommonName() {
    RespID responderId = origin.getOCSPSource().getContainedOCSPResponses().get(0).getResponderId();
    return getCN(responderId.toASN1Object().getName());
  }

  private String getCN(X500Name x500Name) {
    return x500Name.getRDNs(new ASN1ObjectIdentifier("2.5.4.3"))[0].getTypesAndValues()[0].getValue().toString();
  }

  public String getPolicy() {
    throw new NotYetImplementedException();
  }

  public String getPostalCode() {
    return signerLocation.getPostalCode();
  }

  public Date getProducedAt() {
    return origin.getOCSPSource().getContainedOCSPResponses().get(0).getProducedAt();
  }

  public SignatureProfile getProfile() {
    if (origin.getSignatureTimestamps() != null && origin.getSignatureTimestamps().size() > 0)
      return SignatureProfile.TS;
    return SignatureProfile.NONE;
  }

  public String getSignatureMethod() {
    return origin.getDigestAlgorithm().getXmlId();
  }

  public List<String> getSignerRoles() {
    return Arrays.asList(origin.getClaimedSignerRoles());
  }

  public X509Cert getSigningCertificate() {
    return new X509Cert(origin.getSigningCertificateToken().getCertificate());
  }

  public Date getSigningTime() {
    return origin.getSigningTime();
  }

  public URI getSignaturePolicyURI() {
    throw new NotYetImplementedException();
  }

  public String getStateOrProvince() {
    return signerLocation.getStateOrProvince();
  }

  public X509Cert getTimeStampTokenCertificate() {
    if (origin.getSignatureTimestamps() == null || origin.getSignatureTimestamps().size() == 0) {
      throw new CertificateNotFoundException("TimeStamp certificate not found");
    }
    return new X509Cert(origin.getSignatureTimestamps().get(0).getIssuerToken().getCertificate());
  }

  public List<DigiDoc4JException> validate(Validate validationType) {
    return validationErrors;
  }

  public List<DigiDoc4JException> validate() {
    return validate(Validate.VALIDATE_FULL);
  }

  public byte[] getRawSignature() {
    return origin.getSignatureValue().getFirstChild().getNodeValue().getBytes();
  }
}
