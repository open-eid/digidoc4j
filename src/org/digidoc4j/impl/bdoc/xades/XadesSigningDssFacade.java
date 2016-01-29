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

import static eu.europa.esig.dss.DigestAlgorithm.forXML;

import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

import org.digidoc4j.DataFile;
import org.digidoc4j.exceptions.ContainerWithoutFilesException;
import org.digidoc4j.impl.bdoc.SKCommonCertificateVerifier;
import org.digidoc4j.impl.bdoc.SKTimestampDataLoader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.signature.StreamDocument;
import eu.europa.esig.dss.BLevelParameters;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.EncryptionAlgorithm;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.Policy;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.SignerLocation;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.client.tsp.OnlineTSPSource;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.x509.CertificateSource;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.ocsp.OCSPSource;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

public class XadesSigningDssFacade {

  private static final Logger logger = LoggerFactory.getLogger(XadesSigningDssFacade.class);
  private static final int ONE_MB_IN_BYTES = 1048576;
  private DocumentSignatureService<XAdESSignatureParameters> service;
  private XAdESSignatureParameters xAdESSignatureParameters = new XAdESSignatureParameters();
  private CertificateVerifier certificateVerifier = new SKCommonCertificateVerifier();
  private String timestampServerUrl;
  private long cachedFileSizeInMB;
  private boolean bigFilesSupportEnabled = false;

  public XadesSigningDssFacade(String timestampServerUrl) {
    this.timestampServerUrl = timestampServerUrl;
    initDefaultXadesParameters();
    initCertificateVerifier();
    initXadesService();
  }

  public byte[] getDataToSign(Collection<DataFile> dataFiles) {
    logger.debug("Getting data to sign from DSS");
    DSSDocument dssDocumentToSign = transformSignableAttachment(dataFiles);
    ToBeSigned dataToSign = service.getDataToSign(dssDocumentToSign, xAdESSignatureParameters);
    logger.debug("Got data to sign from DSS");
    return dataToSign.getBytes();
  }

  public DSSDocument signDocument(byte[] signatureValue, Collection<DataFile> dataFiles) {
    logger.debug("Signing document with DSS");
    SignatureValue dssSignatureValue = new SignatureValue(xAdESSignatureParameters.getSignatureAlgorithm(), signatureValue);
    DSSDocument dssDocument = transformSignableAttachment(dataFiles);
    DSSDocument signedDocument = service.signDocument(dssDocument, xAdESSignatureParameters, dssSignatureValue);
    logger.debug("Finished signing document with DSS");
    return signedDocument;
  }

  public DSSDocument extendSignature(DSSDocument xadesSignature, DSSDocument detachedContent) {
    logger.debug("Extending signature with DSS");
    xAdESSignatureParameters.setDetachedContent(detachedContent);
    DSSDocument extendedSignature = service.extendDocument(xadesSignature, xAdESSignatureParameters);
    logger.debug("Finished extending signature with DSS");
    return extendedSignature;
  }

  public void setSigningCertificate(X509Certificate certificate) {
    CertificateToken signingCertificate = new CertificateToken(certificate);
    xAdESSignatureParameters.setSigningCertificate(signingCertificate);
  }

  public void setBigFilesSupportEnabled(boolean bigFilesSupportEnabled) {
    this.bigFilesSupportEnabled = bigFilesSupportEnabled;
  }

  public void setCachedFileSizeInMB(long cachedFileSizeInMB) {
    this.cachedFileSizeInMB = cachedFileSizeInMB;
  }

  public void setOcspSource(OCSPSource ocspSource) {
    certificateVerifier.setOcspSource(ocspSource);
  }

  public void setCertificateSource(CertificateSource certificateSource) {
    certificateVerifier.setTrustedCertSource(certificateSource);
  }

  public void setSignatureDigestAlgorithm(org.digidoc4j.DigestAlgorithm digestAlgorithm) {
    xAdESSignatureParameters.setDigestAlgorithm(convertToDssDigestAlgorithm(digestAlgorithm));
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
    xAdESSignatureParameters.setDeterministicId(signatureId);
  }

  private void initDefaultXadesParameters() {
    xAdESSignatureParameters.clearCertificateChain();
    xAdESSignatureParameters.bLevel().setSigningDate(new Date());
    xAdESSignatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
    xAdESSignatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);
    xAdESSignatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
  }

  private void initCertificateVerifier() {
    certificateVerifier.setCrlSource(null); //Disable CRL checks
    certificateVerifier.setSignatureCRLSource(null); //Disable CRL checks
  }

  private void initXadesService() {
    service = new XAdESService(certificateVerifier);
    OnlineTSPSource tspSource = new OnlineTSPSource(timestampServerUrl);
    SKTimestampDataLoader dataLoader = new SKTimestampDataLoader();
    tspSource.setDataLoader(dataLoader);
    service.setTspSource(tspSource);
  }

  private DSSDocument transformSignableAttachment(Collection<DataFile> dataFiles) {
    logger.debug("");
    if (dataFiles.size() == 0) {
      logger.error("Container does not contain any data files");
      throw new ContainerWithoutFilesException();
    }
    Iterator<DataFile> iterator = dataFiles.iterator();
    DSSDocument firstAttachment = getDssDocumentFromDataFile(iterator.next());
    DSSDocument lastAttachment = firstAttachment;
    while (iterator.hasNext()) {
      DataFile dataFile = iterator.next();
      DSSDocument newAttachment = getDssDocumentFromDataFile(dataFile);
      lastAttachment.setNextDocument(newAttachment);
      lastAttachment = newAttachment;
    }

    return firstAttachment;
  }

  private DSSDocument getDssDocumentFromDataFile(DataFile dataFile) {
    logger.debug("");
    DSSDocument attachment;
    MimeType mimeType = MimeType.fromMimeTypeString(dataFile.getMediaType());
    String dataFileName = dataFile.getName();

    if (bigFilesSupportEnabled && dataFile.getFileSize() > cachedFileSizeInMB * ONE_MB_IN_BYTES) {
      attachment = new StreamDocument(dataFile.getStream(), dataFileName, mimeType);
    } else {
      attachment = new InMemoryDocument(dataFile.getBytes(), dataFileName, mimeType);
    }
    return attachment;
  }

  private eu.europa.esig.dss.DigestAlgorithm convertToDssDigestAlgorithm(org.digidoc4j.DigestAlgorithm digestAlgorithm) {
    return forXML(digestAlgorithm.toString());
  }
}
