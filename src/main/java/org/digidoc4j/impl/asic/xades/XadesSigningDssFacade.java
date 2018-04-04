/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.asic.xades;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import org.digidoc4j.DataFile;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.impl.asic.DetachedContentCreator;
import org.digidoc4j.impl.asic.SKCommonCertificateVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import eu.europa.esig.dss.BLevelParameters;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.EncryptionAlgorithm;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.Policy;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.SignerLocation;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.asic.ASiCNamespace;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.x509.CertificateSource;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.ocsp.OCSPSource;
import eu.europa.esig.dss.x509.tsp.TSPSource;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

/**
 * Facade class for DSS Xades signing functionality.
 */
public class XadesSigningDssFacade {

  private static final Logger logger = LoggerFactory.getLogger(XadesSigningDssFacade.class);
  private XAdESService xAdESService;
  private XAdESSignatureParameters xAdESSignatureParameters = new XAdESSignatureParameters();
  private List<DSSDocument> detachedContentList = null;
  private CertificateVerifier certificateVerifier = new SKCommonCertificateVerifier();

  /**
   * Constructor
   */
  public XadesSigningDssFacade() {
    initDefaultXadesParameters();
    initCertificateVerifier();
    initXadesMultipleService();
  }

  /**
   * Method getDataToSign converts File into byte array
   * @param dataFiles List of files to be signed
   * @return Data in byte array, not digest!
   */
  public byte[] getDataToSign(Collection<DataFile> dataFiles) {
    logger.debug("Getting data to sign from DSS");
    DetachedContentCreator detachedContentCreator = null;
    try {
      detachedContentCreator = new DetachedContentCreator().populate(dataFiles);
    } catch (Exception e) {
      logger.error("Error in datafiles processing: " + e.getMessage());
      throw new DigiDoc4JException(e);
    }
    detachedContentList = detachedContentCreator.getDetachedContentList();
    xAdESSignatureParameters.setDetachedContents(detachedContentList);
    logger.debug("Signature parameters: " + xAdESSignatureParameters.toString());
    ToBeSigned dataToSign = xAdESService.getDataToSign(detachedContentList, xAdESSignatureParameters);

    logger.debug("Got data to sign from DSS");
    return dataToSign.getBytes();
  }

  /**
   * Method for signing and adding files into container.
   * @param signatureValue Signature value in byte array
   * @param dataFiles Collection of files
   * @return Container what is containing datafiles and signature
   */
  public DSSDocument signDocument(byte[] signatureValue, Collection<DataFile> dataFiles) {
    logger.debug("Signing document with DSS");
    if (detachedContentList == null) {
      DetachedContentCreator detachedContentCreator = null;
      try {
        detachedContentCreator = new DetachedContentCreator().populate(dataFiles);
      } catch (Exception e) {
        logger.error("Error in datafiles processing: " + e.getMessage());
        throw new DigiDoc4JException(e);
      }
      detachedContentList = detachedContentCreator.getDetachedContentList();
    }
    logger.debug("Signature parameters: " + xAdESSignatureParameters.toString());
    SignatureValue dssSignatureValue = new SignatureValue(xAdESSignatureParameters.getSignatureAlgorithm(),
        signatureValue);
    DSSDocument signedDocument;
    try {
      signedDocument = xAdESService.signDocument(detachedContentList, xAdESSignatureParameters, dssSignatureValue);
    } catch (DSSException e) {
      logger.warn("Signing document in DSS failed:" + e.getMessage());
      throw new TechnicalException("Got error in signing process: ", e);
    }
    DSSDocument correctedSignedDocument = surroundWithXadesXmlTag(signedDocument);
    return correctedSignedDocument;
  }

  @Deprecated
  public DSSDocument extendSignature(DSSDocument xadesSignature, DSSDocument detachedContent) {
    logger.debug("Extending signature with DSS");
    xAdESSignatureParameters.setDetachedContents(Arrays.asList(detachedContent));
    DSSDocument extendedSignature = xAdESService.extendDocument(xadesSignature, xAdESSignatureParameters);
    logger.debug("Finished extending signature with DSS");
    return extendedSignature;
  }

  public DSSDocument extendSignature(DSSDocument xadesSignature, List<DSSDocument> detachedContents) {
    logger.debug("Extending signature with DSS");
    xAdESSignatureParameters.setDetachedContents(detachedContents);
    DSSDocument extendedSignature = xAdESService.extendDocument(xadesSignature, xAdESSignatureParameters);
    logger.debug("Finished extending signature with DSS");
    return extendedSignature;
  }

  public void setSigningCertificate(X509Certificate certificate) {
    CertificateToken signingCertificate = new CertificateToken(certificate);
    xAdESSignatureParameters.setSigningCertificate(signingCertificate);
  }

  public void setOcspSource(OCSPSource ocspSource) {
    certificateVerifier.setOcspSource(ocspSource);
  }

  public void setCertificateSource(CertificateSource certificateSource) {
    certificateVerifier.setTrustedCertSource(certificateSource);
  }

  public void setSignatureDigestAlgorithm(org.digidoc4j.DigestAlgorithm digestAlgorithm) {
    xAdESSignatureParameters.setDigestAlgorithm(digestAlgorithm.getDssDigestAlgorithm());
  }

  public void setEncryptionAlgorithm(EncryptionAlgorithm encryptionAlgorithm) {
    xAdESSignatureParameters.setEncryptionAlgorithm(encryptionAlgorithm);
  }

  public void setSignerLocation(SignerLocation signerLocation) {
    xAdESSignatureParameters.bLevel().setSignerLocation(signerLocation);
  }

  public void setSignerRoles(Collection<String> signerRoles) {
    if (signerRoles != null && !signerRoles.isEmpty()) {
      BLevelParameters bLevelParameters = xAdESSignatureParameters.bLevel();
      bLevelParameters.setClaimedSignerRoles(new ArrayList<String>(signerRoles));
    }
  }

  public void setSignaturePolicy(Policy signaturePolicy) {
    xAdESSignatureParameters.bLevel().setSignaturePolicy(signaturePolicy);
  }

  public void setSignatureLevel(SignatureLevel signatureLevel) {
    xAdESSignatureParameters.setSignatureLevel(signatureLevel);
  }

  public String getSignatureId() {
    return xAdESSignatureParameters.getDeterministicId();
  }

  public void setSignatureId(String signatureId) {
    logger.debug("Setting deterministic id: " + signatureId);
    //TODO find solution for method setDeterministicId(...)
    xAdESSignatureParameters.setDeterministicId(signatureId);
  }

  public void setSigningDate(Date signingDate) {
    xAdESSignatureParameters.getBLevelParams().setSigningDate(signingDate);
  }

  public void setEn319132(boolean isSigningCertificateV2) {
    xAdESSignatureParameters.setEn319132(isSigningCertificateV2);
  }

  public void getEn319132() {
    xAdESSignatureParameters.isEn319132();
  }

  public void setTspSource(TSPSource tspSource) {
    xAdESService.setTspSource(tspSource);
  }

  private void initDefaultXadesParameters() {
    xAdESSignatureParameters.clearCertificateChain();
    xAdESSignatureParameters.getBLevelParams().setSigningDate(new Date());
    xAdESSignatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
    xAdESSignatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);
    xAdESSignatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
    xAdESSignatureParameters.setSigningCertificateDigestMethod(DigestAlgorithm.SHA256);
    xAdESSignatureParameters.setEn319132(false);
  }

  private void initCertificateVerifier() {
    certificateVerifier.setCrlSource(null); //Disable CRL checks
    certificateVerifier.setSignatureCRLSource(null); //Disable CRL checks
  }

  private void initXadesMultipleService() {
    xAdESService = new XAdESService(certificateVerifier);
  }

  private DSSDocument surroundWithXadesXmlTag(DSSDocument signedDocument) {
    logger.debug("Surrounding signature document with xades tag");
    Document signatureDom = DomUtils.buildDOM(signedDocument);
    Element signatureElement = signatureDom.getDocumentElement();
    Document document = XmlDomCreator.createDocument(ASiCNamespace.NS, XmlDomCreator.ASICS_NS, signatureElement);
    byte[] documentBytes = DSSXMLUtils.serializeNode(document);
    return new InMemoryDocument(documentBytes);
  }

}
