/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc;

import static eu.europa.esig.dss.DSSXMLUtils.createDocument;

import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.ocsp.RespID;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.X509Cert;
import org.digidoc4j.exceptions.CertificateNotFoundException;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.NotYetImplementedException;
import org.digidoc4j.impl.bdoc.xades.XadesSignatureValidator;
import org.digidoc4j.impl.bdoc.xades.XadesSignatureWrapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

import eu.europa.esig.dss.ASiCNamespaces;
import eu.europa.esig.dss.DSSXMLUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.asic.signature.ASiCService;
import eu.europa.esig.dss.validation.SignatureProductionPlace;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.xades.validation.XAdESSignature;

/**
 * BDoc signature implementation.
 */
public class BDocSignature implements Signature {
  private static final Logger logger = LoggerFactory.getLogger(BDocSignature.class);
  private SignatureProductionPlace signerLocation;
  private List<DigiDoc4JException> validationErrors;
  private XadesSignatureWrapper signatureWrapper;
  private XadesSignatureValidator validator;

  /**
   * Create a new BDoc signature.
   *
   * @param signature XAdES signature to use for the BDoc signature
   */
  @Deprecated
  public BDocSignature(XAdESSignature signature) {
    signerLocation = signature.getSignatureProductionPlace();

    this.signatureWrapper = new XadesSignatureWrapper(signature);
    validationErrors = new ArrayList<>();
    logger.debug("New BDoc signature created");
  }

  public BDocSignature(XadesSignatureWrapper signatureWrapper, XadesSignatureValidator validator) {
    this.signatureWrapper = signatureWrapper;
    this.validator = validator;
    this.signerLocation = signatureWrapper.getSignatureProductionPlace();
    logger.debug("New BDoc signature created");
  }

  @Override
  public String getCity() {
    return signerLocation == null ? null : signerLocation.getCity();
  }

  @Override
  public String getCountryName() {
    return signerLocation == null ? null : signerLocation.getCountryName();
  }

  @Override
  public String getId() {
    return getOrigin().getId();
  }

  @Override
  public byte[] getOCSPNonce() {
    logger.warn("Not yet implemented");
    throw new NotYetImplementedException();
  }

  @Override
  public X509Cert getOCSPCertificate() {
    logger.debug("");

    if (getOrigin().getOCSPSource().getContainedOCSPResponses().size() == 0)
      return null;

    String ocspCN = getOCSPCommonName();
    for (CertificateToken cert : getOrigin().getCertPool().getCertificateTokens()) {
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
    RespID responderId = getOrigin().getOCSPSource().getContainedOCSPResponses().get(0).getResponderId();
    String commonName = getCN(responderId.toASN1Object().getName());
    logger.debug("OCSP common name: " + commonName);
    return commonName;
  }

  private String getCN(X500Name x500Name) {
    String name = x500Name.getRDNs(new ASN1ObjectIdentifier("2.5.4.3"))[0].getTypesAndValues()[0].getValue().toString();
    logger.debug("Common name: " + name);
    return name;
  }

  @Override
  @Deprecated
  public String getPolicy() {
    logger.warn("Not yet implemented");
    throw new NotYetImplementedException();
  }

  @Override
  public String getPostalCode() {
    return signerLocation == null ? null : signerLocation.getPostalCode();
  }

  @Override
  public Date getOCSPResponseCreationTime() {
    return signatureWrapper.getOCSPResponseCreationTime();
  }

  @Override
  @Deprecated
  public Date getProducedAt() {
    return getOCSPResponseCreationTime();
  }

  @Override
  public Date getTimeStampCreationTime() {
    return signatureWrapper.getTimeStampCreationTime();
  }

  /**
   * Trusted signing time should be taken based on the profile:
   * BES should return null,
   * LT_TM should return OCSP response creation time and
   * LT should return Timestamp creation time.
   *
   * @return signing time backed by a trusted service (not just a user's computer clock time).
   */
  @Override
  public Date getTrustedSigningTime() {
    return signatureWrapper.getTrustedSigningTime();
  }

  @Override
  public SignatureProfile getProfile() {
    return signatureWrapper.getProfile();
  }

  @Override
  public String getSignatureMethod() {
    String xmlId = getOrigin().getDigestAlgorithm().getXmlId();
    logger.debug("Signature method: " + xmlId);
    return xmlId;
  }

  @Override
  public List<String> getSignerRoles() {
    String[] claimedSignerRoles = getOrigin().getClaimedSignerRoles();
    return claimedSignerRoles == null ? null : Arrays.asList(claimedSignerRoles);
  }

  @Override
  public X509Cert getSigningCertificate() {
    return new X509Cert(getOrigin().getSigningCertificateToken().getCertificate());
  }

  @Override
  public Date getClaimedSigningTime() {
    Date signingTime = getOrigin().getSigningTime();
    logger.debug("Signing time: " + signingTime);
    return signingTime;
  }

  @Override
  public Date getSigningTime() {
    return getClaimedSigningTime();
  }

  @Override
  @Deprecated
  public URI getSignaturePolicyURI() {
    logger.warn("Not yet implemented");
    throw new NotYetImplementedException();
  }

  @Override
  public String getStateOrProvince() {
    return signerLocation == null ? null : signerLocation.getStateOrProvince();
  }

  @Override
  public X509Cert getTimeStampTokenCertificate() {
    logger.debug("");
    if (getOrigin().getSignatureTimestamps() == null || getOrigin().getSignatureTimestamps().size() == 0) {
      CertificateNotFoundException exception = new CertificateNotFoundException("TimeStamp certificate not found");
      logger.error(exception.getMessage());
      throw exception;
    }
    return new X509Cert(getOrigin().getSignatureTimestamps().get(0).getIssuerToken().getCertificate());
  }

  @Override
  public List<DigiDoc4JException> validate() {
    logger.debug("Validating signature");
    if(validationErrors == null) {
      validationErrors = validator.extractValidationErrors();
      logger.info("Signature has " + validationErrors.size() + " validation errors");
    } else {
      logger.debug("Using existing validation errors with error count: " + validationErrors.size());
    }
    return validationErrors;
  }

  @Override
  public byte[] getAdESSignature() {
    logger.debug("");
    Document document = createDocument(ASiCNamespaces.ASiC, ASiCService.ASICS_NS, getOrigin().getSignatureElement());
    return DSSXMLUtils.transformDomToByteArray(document);
  }

  @Override
  @Deprecated
  public byte[] getRawSignature() {
    return getAdESSignature();
  }

  public XAdESSignature getOrigin() {
    return signatureWrapper.getOrigin();
  }

  List<DigiDoc4JException> getValidationErrors() {
    return validationErrors;
  }

  public void setValidationErrors(List<DigiDoc4JException> validationErrors) {
    this.validationErrors = validationErrors;
  }

  DigestAlgorithm getSignatureDigestAlgorithm() {
    return getOrigin().getDigestAlgorithm();
  }
}
