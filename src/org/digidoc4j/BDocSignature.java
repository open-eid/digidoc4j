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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import static org.digidoc4j.api.Container.SignatureProfile;


/**
 * BDoc signature implementation.
 */
public class BDocSignature extends Signature {
  final Logger logger = LoggerFactory.getLogger(BDocSignature.class);
  private XAdESSignature origin;
  private SignatureProductionPlace signerLocation;
  private List<DigiDoc4JException> validationErrors = new ArrayList<DigiDoc4JException>();

  /**
   * Create a new BDoc signature.
   *
   * @param signature XAdES signature to use for the BDoc signature
   */
  public BDocSignature(XAdESSignature signature) {
    origin = signature;
    signerLocation = signature.getSignatureProductionPlace();
  }

  /**
   * * Create a new BDOC signature.
   *
   * @param signature        XAdES signature to use for the BDoc signature
   * @param validationErrors list of DigiDoc4J exceptions to add to the signature
   */
  public BDocSignature(XAdESSignature signature, List<DigiDoc4JException> validationErrors) {
    origin = signature;
    signerLocation = signature.getSignatureProductionPlace();
    this.validationErrors = validationErrors;
  }

  @Override
  public void setCertificate(X509Cert cert) {
    logger.error("Not yet implemented");
    throw new NotYetImplementedException();
  }

  @Override
  public String getCity() {
    return signerLocation.getCity();
  }

  @Override
  public String getCountryName() {
    return signerLocation.getCountryName();
  }

  @Override
  public String getId() {
    return origin.getId();
  }

  @Override
  public byte[] getNonce() {
    logger.error("Not yet implemented");
    throw new NotYetImplementedException();
  }

  @Override  //TODO Should this throw a DigiDoc4JException instead of CertificateNotFoundException
  public X509Cert getOCSPCertificate() {
    String ocspCN = getOCSPCommonName();
    for (CertificateToken cert : origin.getCertPool().getCertificateTokens()) {
      String value = getCN(new X500Name(cert.getSubjectX500Principal().getName()));
      if (value.equals(ocspCN))
        return new X509Cert(cert.getCertificate());
    }
    CertificateNotFoundException exception =
        new CertificateNotFoundException("Certificate for " + ocspCN + " not found in TSL");
    logger.error(exception.getMessage());
    throw exception;
  }

  private String getOCSPCommonName() {
    RespID responderId = origin.getOCSPSource().getContainedOCSPResponses().get(0).getResponderId();
    return getCN(responderId.toASN1Object().getName());
  }

  private String getCN(X500Name x500Name) {
    return x500Name.getRDNs(new ASN1ObjectIdentifier("2.5.4.3"))[0].getTypesAndValues()[0].getValue().toString();
  }

  @Override
  public String getPolicy() {
    logger.error("Not yet implemented");
    throw new NotYetImplementedException();
  }

  @Override
  public String getPostalCode() {
    return signerLocation.getPostalCode();
  }

  @Override
  public Date getProducedAt() {
    return origin.getOCSPSource().getContainedOCSPResponses().get(0).getProducedAt();
  }

  @Override
  public SignatureProfile getProfile() {
    if (origin.getSignatureTimestamps() != null && origin.getSignatureTimestamps().size() > 0)
      return SignatureProfile.TS;
    return SignatureProfile.NONE;
  }

  @Override
  public String getSignatureMethod() {
    return origin.getDigestAlgorithm().getXmlId();
  }

  @Override
  public List<String> getSignerRoles() {
    return Arrays.asList(origin.getClaimedSignerRoles());
  }

  @Override
  public X509Cert getSigningCertificate() {
    return new X509Cert(origin.getSigningCertificateToken().getCertificate());
  }

  @Override
  public Date getSigningTime() {
    return origin.getSigningTime();
  }

  @Override
  public URI getSignaturePolicyURI() {
    logger.error("Not yet implemented");
    throw new NotYetImplementedException();
  }

  @Override
  public String getStateOrProvince() {
    return signerLocation.getStateOrProvince();
  }

  @Override
  public X509Cert getTimeStampTokenCertificate() {
    if (origin.getSignatureTimestamps() == null || origin.getSignatureTimestamps().size() == 0) {
      CertificateNotFoundException exception = new CertificateNotFoundException("TimeStamp certificate not found");
      logger.error(exception.getMessage());
      throw exception;
    }
    return new X509Cert(origin.getSignatureTimestamps().get(0).getIssuerToken().getCertificate());
  }

  @Override
  public List<DigiDoc4JException> validate(Validate validationType) {
    return validationErrors;
  }

  @Override
  public List<DigiDoc4JException> validate() {
    return validate(Validate.VALIDATE_FULL);
  }

  @Override
  public byte[] getRawSignature() {
    return origin.getSignatureValue().getFirstChild().getNodeValue().getBytes();
  }
}
