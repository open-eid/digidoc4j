/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc.xades;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.io.IOUtils;
import org.digidoc4j.DataFile;
import org.digidoc4j.impl.bdoc.SKCommonCertificateVerifier;
import org.digidoc4j.impl.bdoc.asic.DetachedContentCreator;
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
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.x509.CertificateSource;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.ocsp.OCSPSource;
import eu.europa.esig.dss.x509.tsp.TSPSource;

import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

public class XadesSigningDssFacade {

  private static final Logger logger = LoggerFactory.getLogger(XadesSigningDssFacade.class);
  private DocumentSignatureService<XAdESSignatureParameters> service;
  private XAdESSignatureParameters xAdESSignatureParameters = new XAdESSignatureParameters();
  private CertificateVerifier certificateVerifier = new SKCommonCertificateVerifier();

  public XadesSigningDssFacade() {
    initDefaultXadesParameters();
    initCertificateVerifier();
    initXadesService();
  }

  public byte[] getDataToSign(Collection<DataFile> dataFiles) {
    logger.debug("Getting data to sign from DSS");
    DetachedContentCreator detachedContentCreator = new DetachedContentCreator().populate(dataFiles);
    DSSDocument dssDocumentToSign = detachedContentCreator.getFirstDetachedContent();
    logger.debug("Signature parameters: " + xAdESSignatureParameters.toString());
    ToBeSigned dataToSign = service.getDataToSign(dssDocumentToSign, xAdESSignatureParameters);
    logger.debug("Got data to sign from DSS");
    return dataToSign.getBytes();
  }

  public DSSDocument signDocument(byte[] signatureValue, Collection<DataFile> dataFiles) {
    logger.debug("Signing document with DSS");
    SignatureValue dssSignatureValue = new SignatureValue(xAdESSignatureParameters.getSignatureAlgorithm(), signatureValue);
    DetachedContentCreator detachedContentCreator = new DetachedContentCreator().populate(dataFiles);
    DSSDocument dssDocument = detachedContentCreator.getFirstDetachedContent();
    logger.debug("Signature parameters: " + xAdESSignatureParameters.toString());
    DSSDocument signedDocument = service.signDocument(dssDocument, xAdESSignatureParameters, dssSignatureValue);
    logger.debug("Finished signing document with DSS");
    DSSDocument correctedSignedDocument = surroundWithXadesXmlTag(signedDocument);
    return correctedSignedDocument;
  }

  public DSSDocument extendSignature(DSSDocument xadesSignature, DSSDocument detachedContent) {
    logger.debug("Extending signature with DSS");
    xAdESSignatureParameters.setDetachedContents(Arrays.asList(detachedContent));
    DSSDocument extendedSignature = service.extendDocument(xadesSignature, xAdESSignatureParameters);
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
    BLevelParameters bLevelParameters = xAdESSignatureParameters.bLevel();
    for (String signerRole : signerRoles) {
      bLevelParameters.addClaimedSignerRole(signerRole);
    }
  }

  public void setSignaturePolicy(Policy signaturePolicy) {
    xAdESSignatureParameters.bLevel().setSignaturePolicy(signaturePolicy);
  }

  public void setSignatureLevel(SignatureLevel signatureLevel) {
    xAdESSignatureParameters.setSignatureLevel(signatureLevel);
  }

  public void setSignatureId(String signatureId) {
    logger.debug("Setting deterministic id: " + signatureId);
    //TODO find solution for method setDeterministicId(...)
    xAdESSignatureParameters.setDeterministicId(signatureId);
  }

  public String getSignatureId() {
    return xAdESSignatureParameters.getDeterministicId();
  }

  public void setSigningDate(Date signingDate) {
    xAdESSignatureParameters.getBLevelParams().setSigningDate(signingDate);
  }

  public void setTspSource(TSPSource tspSource) {
    service.setTspSource(tspSource);
  }

  private void initDefaultXadesParameters() {
    xAdESSignatureParameters.clearCertificateChain();
    xAdESSignatureParameters.bLevel().setSigningDate(new Date());
    xAdESSignatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
    xAdESSignatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);
    xAdESSignatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
    xAdESSignatureParameters.setSigningCertificateDigestMethod(DigestAlgorithm.SHA256);
  }

  private void initCertificateVerifier() {
    certificateVerifier.setCrlSource(null); //Disable CRL checks
    certificateVerifier.setSignatureCRLSource(null); //Disable CRL checks
  }

  private void initXadesService() {
    service = new XAdESService(certificateVerifier);
  }

  private DSSDocument surroundWithXadesXmlTag(DSSDocument signedDocument) {
    logger.debug("Surrounding signature document with xades tag");
    //TODO test - now DomUtils in use
    Document signatureDom = DomUtils.buildDOM(signedDocument);
    Element signatureElement = signatureDom.getDocumentElement();
    Document document = XmlDomCreator.createDocument(ASiCNamespace.NS, XmlDomCreator.ASICS_NS, signatureElement);
    byte[] documentBytes = DSSXMLUtils.serializeNode(document);
    return new InMemoryDocument(documentBytes);
  }

}
