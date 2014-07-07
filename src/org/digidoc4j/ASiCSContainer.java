package org.digidoc4j;

import eu.europa.ec.markt.dss.parameter.BLevelParameters;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.*;
import eu.europa.ec.markt.dss.signature.asic.ASiCSService;
import eu.europa.ec.markt.dss.validation102853.CommonCertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.asic.ASiCXMLDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.https.CommonsDataLoader;
import eu.europa.ec.markt.dss.validation102853.report.Conclusion;
import eu.europa.ec.markt.dss.validation102853.report.SimpleReport;
import eu.europa.ec.markt.dss.validation102853.tsl.TrustedListsCertificateSource;
import eu.europa.ec.markt.dss.validation102853.tsp.OnlineTSPSource;
import org.digidoc4j.api.DataFile;
import org.digidoc4j.api.Signature;
import org.digidoc4j.api.Signer;
import org.digidoc4j.api.exceptions.DigiDoc4JException;
import org.digidoc4j.api.exceptions.NotYetImplementedException;
import org.digidoc4j.api.exceptions.TwoSignaturesNotAllowedException;
import prototype.SKOnlineOCSPSource;

import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static eu.europa.ec.markt.dss.parameter.BLevelParameters.SignerLocation;
import static org.apache.commons.lang.StringUtils.isEmpty;

/**
 * Experimental code to implement ASiC-S container. There is lot's of duplication with BDocContainer. When experimenting is finished duplication is removed
 */
public class ASiCSContainer implements ContainerInterface {

  private CommonCertificateVerifier commonCertificateVerifier;
  protected DocumentSignatureService asicService;
  final private Map<String, DataFile> dataFiles = new HashMap<String, DataFile>();
  protected SignatureParameters signatureParameters;
  protected DSSDocument signedDocument;
  private List<Signature> signatures = new ArrayList<Signature>();
  eu.europa.ec.markt.dss.DigestAlgorithm digestAlgorithm = eu.europa.ec.markt.dss.DigestAlgorithm.SHA256;

  /**
   * Create a new container object of ASIC_E type Container.
   */
  public ASiCSContainer() {
    signatureParameters = new SignatureParameters();
    signatureParameters.setSignatureLevel(SignatureLevel.ASiC_S_BASELINE_B);
    signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
    commonCertificateVerifier = new CommonCertificateVerifier();

    asicService = new ASiCSService(commonCertificateVerifier);
  }

  /**
   * Opens the container from a file.
   *
   * @param path container file name with path
   */
  public ASiCSContainer(String path) {
    signedDocument = new FileDocument(path);
    SignedDocumentValidator validator = ASiCXMLDocumentValidator.fromDocument(signedDocument);
    DSSDocument externalContent = validator.getExternalContent();

    dataFiles.put(externalContent.getName(), new DataFile(externalContent.getBytes(), externalContent.getName(),
        externalContent.getMimeType().getCode()));
  }

  @Override
  public void addDataFile(String path, String mimeType) {
    if (dataFiles.size() >= 1) throw new DigiDoc4JException("ASiCS supports only one attachment");
    dataFiles.put(path, new DataFile(path, mimeType));
  }

  @Override
  public void addDataFile(InputStream is, String fileName, String mimeType) {
    DataFile dataFile;
    try {
      dataFile = new DataFile(org.apache.commons.io.IOUtils.toByteArray(is), fileName, mimeType);
      dataFiles.put(fileName, dataFile);
    } catch (IOException e) {
      throw new DigiDoc4JException(e);
    }
  }

  @Override
  public void addRawSignature(byte[] signature) {
    throw new NotYetImplementedException();
  }

  @Override
  public void addRawSignature(InputStream signatureStream) {
    throw new NotYetImplementedException();
  }

  @Override
  public List<DataFile> getDataFiles() {
    return new ArrayList<DataFile>(dataFiles.values());
  }

  @Override
  public void removeDataFile(String fileName) {
    if (dataFiles.remove(fileName) == null) throw new DigiDoc4JException("File not found");
  }

  @Override
  public void removeSignature(int signatureId) {
    throw new NotYetImplementedException();
  }

  @Override
  public void save(String path) {
    documentMustBeInitializedCheck();
    signedDocument.save(path);
  }

  private void documentMustBeInitializedCheck() {
    if (signedDocument == null)
      throw new NotYetImplementedException();
  }

  @Override
  public Signature sign(Signer signer) {
    if (signatures.size() >= 1) throw new TwoSignaturesNotAllowedException("Only one signature allowed");
    addSignerInformation(signer);
    commonCertificateVerifier.setTrustedCertSource(getTSL());
    commonCertificateVerifier.setOcspSource(new SKOnlineOCSPSource());

    asicService = new ASiCSService(commonCertificateVerifier);
    asicService.setTspSource(new OnlineTSPSource("http://tsa01.quovadisglobal.com/TSS/HttpTspServer"));
    signatureParameters.setSigningCertificate(signer.getCertificate().getX509Certificate());

    //TODO not working with big files
    DSSDocument toSignDocument = new InMemoryDocument(getFirstDataFile().getBytes(), getFirstDataFile().getFileName(),
        MimeType.fromCode(getFirstDataFile().getMediaType()));

    byte[] dataToSign = asicService.getDataToSign(toSignDocument, signatureParameters);
    byte[] signatureValue = signer.sign(signatureParameters.getDigestAlgorithm().getXmlId(), dataToSign);
    signedDocument = asicService.signDocument(toSignDocument, signatureParameters, signatureValue);

    Signature signature = new Signature(new BDocSignature(signatureValue, signatureParameters));
    signatures.add(signature);
    return signature;
  }

  private TrustedListsCertificateSource getTSL() {
    final String lotlUrl = "file:conf/trusted-test-tsl.xml";
    TrustedListsCertificateSource tslCertificateSource = new TrustedListsCertificateSource();
    tslCertificateSource.setDataLoader(new CommonsDataLoader());
    tslCertificateSource.setLotlUrl(lotlUrl);
    tslCertificateSource.setCheckSignature(false);
    tslCertificateSource.init();
    return tslCertificateSource;
  }

  private void addSignerInformation(Signer signer) {
    signatureParameters.setDigestAlgorithm(digestAlgorithm);
    BLevelParameters bLevelParameters = signatureParameters.bLevel();

    if (!(isEmpty(signer.getCity()) && isEmpty(signer.getStateOrProvince()) && isEmpty(signer.getPostalCode()) && isEmpty(signer.getCountry()))) {
      SignerLocation signerLocation = new SignerLocation();
      if (!isEmpty(signer.getCity())) signerLocation.setCity(signer.getCity());
      if (!isEmpty(signer.getStateOrProvince())) signerLocation.setStateOrProvince(signer.getStateOrProvince());
      if (!isEmpty(signer.getPostalCode())) signerLocation.setPostalCode(signer.getPostalCode());
      if (!isEmpty(signer.getCountry())) signerLocation.setCountry(signer.getCountry());
      bLevelParameters.setSignerLocation(signerLocation);
    }
    for (String signerRole : signer.getSignerRoles()) {
      bLevelParameters.addClaimedSignerRole(signerRole);
    }
  }

  public List<DigiDoc4JException> verify() throws ParserConfigurationException {
    documentMustBeInitializedCheck();

    SignedDocumentValidator validator = ASiCXMLDocumentValidator.fromDocument(signedDocument);
    CommonCertificateVerifier verifier = new CommonCertificateVerifier();
    SKOnlineOCSPSource onlineOCSPSource = new SKOnlineOCSPSource();
    verifier.setOcspSource(onlineOCSPSource);

    TrustedListsCertificateSource trustedCertSource = getTSL();

    verifier.setTrustedCertSource(trustedCertSource);
    validator.setCertificateVerifier(verifier);
    File policyFile = new File("conf/constraint.xml");
    validator.validateDocument(policyFile);
    SimpleReport simpleReport = validator.getSimpleReport();

    List<DigiDoc4JException> validationErrors = new ArrayList<DigiDoc4JException>();
    List<String> signatureIds = simpleReport.getSignatureIds();
    for (String signatureId : signatureIds) {
      List<Conclusion.BasicInfo> errors = simpleReport.getErrors(signatureId);
      for (Conclusion.BasicInfo error : errors) {
        validationErrors.add(new DigiDoc4JException(error.toString()));
      }
    }
    System.out.println(simpleReport);

    return validationErrors;
  }

  private DataFile getFirstDataFile() {
    return (DataFile) dataFiles.values().toArray()[0];
  }

  @Override
  public List<Signature> getSignatures() {
    return signatures;
  }

  @Override
  public DocumentType getDocumentType() {
    return DocumentType.ASIC_S;
  }

  @Override
  public void setDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
    this.digestAlgorithm = eu.europa.ec.markt.dss.DigestAlgorithm.forName(digestAlgorithm.name(), eu.europa.ec.markt.dss.DigestAlgorithm.SHA256);
  }
}






