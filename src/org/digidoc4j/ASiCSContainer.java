package org.digidoc4j;

import eu.europa.ec.markt.dss.parameter.BLevelParameters;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.*;
import eu.europa.ec.markt.dss.signature.asic.DigiDoc4JASiCSService;
import eu.europa.ec.markt.dss.validation102853.AdvancedSignature;
import eu.europa.ec.markt.dss.validation102853.CommonCertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.SignatureForm;
import eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.asic.ASiCXMLDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.https.CommonsDataLoader;
import eu.europa.ec.markt.dss.validation102853.ocsp.SKOnlineOCSPSource;
import eu.europa.ec.markt.dss.validation102853.report.Conclusion;
import eu.europa.ec.markt.dss.validation102853.report.SimpleReport;
import eu.europa.ec.markt.dss.validation102853.tsl.TrustedListsCertificateSource;
import eu.europa.ec.markt.dss.validation102853.tsp.OnlineTSPSource;
import eu.europa.ec.markt.dss.validation102853.xades.XAdESSignature;
import org.apache.commons.io.IOUtils;
import org.digidoc4j.api.*;
import org.digidoc4j.api.exceptions.DigiDoc4JException;
import org.digidoc4j.api.exceptions.NotYetImplementedException;
import org.digidoc4j.api.exceptions.SignatureNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static eu.europa.ec.markt.dss.DigestAlgorithm.SHA256;
import static eu.europa.ec.markt.dss.DigestAlgorithm.forName;
import static eu.europa.ec.markt.dss.parameter.BLevelParameters.SignerLocation;
import static org.apache.commons.lang.StringUtils.isEmpty;
import static org.digidoc4j.api.Container.DocumentType.ASIC_S;

/**
 * Experimental code to implement ASiC-S container. There is lot's of duplication with BDocContainer.
 * When experimenting is finished duplication is removed
 */
public class ASiCSContainer extends Container {

  final Logger logger = LoggerFactory.getLogger(ASiCSContainer.class);

  private final Map<String, DataFile> dataFiles = new HashMap<String, DataFile>();
  public static final int FILE_SIZE_TO_STREAM = 1024 * 1000 * 3;
  private CommonCertificateVerifier commonCertificateVerifier;
  protected DocumentSignatureService asicService;
  private SignatureParameters signatureParameters;
  protected DSSDocument signedDocument;
  private List<Signature> signatures = new ArrayList<Signature>();
  eu.europa.ec.markt.dss.DigestAlgorithm digestAlgorithm = SHA256;
  Configuration configuration = null;
  private TrustedListsCertificateSource tslCertificateSource;

  /**
   * Create a new container object of type ASIC_E.
   */
  public ASiCSContainer() {
    logger.debug("");
    configuration = new Configuration();
    signatureParameters = new SignatureParameters();
    signatureParameters.setSignatureLevel(SignatureLevel.ASiC_S_BASELINE_LT);
    signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
    signatureParameters.aSiC().setAsicSignatureForm(SignatureForm.XAdES);

    commonCertificateVerifier = new CommonCertificateVerifier();
    asicService = new DigiDoc4JASiCSService(commonCertificateVerifier);

    logger.debug("New ASiCS container created");
  }

  /**
   * Opens the container from a file.
   *
   * @param path container file name with path
   */
  public ASiCSContainer(String path) {
    this();

    logger.debug("Path: " + path);

    List<DigiDoc4JException> validationErrors;

    signedDocument = new FileDocument(path);
    SignedDocumentValidator validator = ASiCXMLDocumentValidator.fromDocument(signedDocument);
    DSSDocument externalContent = validator.getDetachedContent();

    validate(validator);
    List<AdvancedSignature> signatureList = validator.getSignatures();

    for (AdvancedSignature advancedSignature : signatureList) {
      validationErrors = new ArrayList<DigiDoc4JException>();
      List<Conclusion.BasicInfo> errors = validator.getSimpleReport().getErrors(advancedSignature.getId());
      for (Conclusion.BasicInfo error : errors) {
        String errorMessage = error.toString();
        logger.info(errorMessage);
        validationErrors.add(new DigiDoc4JException(errorMessage));
      }
      signatures.add(new BDocSignature((XAdESSignature) advancedSignature, validationErrors));
    }

    dataFiles.put(externalContent.getName(), new DataFile(externalContent.getBytes(), externalContent.getName(),
        externalContent.getMimeType().getCode()));
    logger.debug("New ASiCS container created");
  }

  /**
   * Load configuration settings
   *
   * @param fileName file containing configuration settings
   */
  public void loadConfiguration(String fileName) {
    logger.debug("");
    configuration.loadConfiguration(fileName);
  }

  @Override
  public void addDataFile(String path, String mimeType) {
    logger.debug("Path: " + path + ", mime type: " + mimeType);
    try {
      FileInputStream is = new FileInputStream(path);
      addDataFile(is, path, mimeType);
      is.close();
    } catch (IOException e) {
      logger.error(e.getMessage());
      throw new DigiDoc4JException(e);
    }
  }

  @Override
  public void addDataFile(InputStream is, String fileName, String mimeType) {
    logger.debug("File name: " + fileName + ", mime type: " + mimeType);
    if (dataFiles.size() >= 1) {
      DigiDoc4JException exception = new DigiDoc4JException("ASiCS supports only one attachment");
      logger.error(exception.getMessage());
      throw exception;
    }

    dataFiles.put(fileName, new DataFile(is, fileName, mimeType));
  }

  @Override
  public void addRawSignature(byte[] signature) {
    logger.debug("");
    InputStream signatureStream = getByteArrayInputStream(signature);
    addRawSignature(signatureStream);
    IOUtils.closeQuietly(signatureStream);
  }

  InputStream getByteArrayInputStream(byte[] signature) {
    logger.debug("");
    return new ByteArrayInputStream(signature);
  }

  @Override //TODO NotYetImplementedException
  public void addRawSignature(InputStream signatureStream) {
//    signatureParameters.setDeterministicId("S" + getSignatures().size());
//    sign(signature);
    logger.warn("Not yet implemented");
    throw new NotYetImplementedException();
  }

  @Override
  public List<DataFile> getDataFiles() {
    logger.debug("");
    return new ArrayList<DataFile>(dataFiles.values());
  }

  @Override
  public void removeDataFile(String fileName) {
    logger.debug("File name: " + fileName);
    if (dataFiles.remove(fileName) == null) {
      DigiDoc4JException exception = new DigiDoc4JException("File not found");
      logger.error(exception.getMessage());
      throw exception;
    }
  }

  @Override
  public void removeSignature(int index) {
    logger.debug("Index: " + index);

    SignedDocumentValidator validator = ASiCXMLDocumentValidator.fromDocument(signedDocument);
    signedDocument = null;
    DSSDocument signingDocument = getSigningDocument();
    signedDocument = validator.removeSignature("S" + index);

    signedDocument = ((DigiDoc4JASiCSService) asicService).createContainer(signingDocument, signedDocument);

    signatures.remove(index);
  }

  @Override
  public void save(String path) {
    logger.debug("Path: " + path);
    documentMustBeInitializedCheck();
    signedDocument.save(path);
  }

  //TODO NotYetImplementedException
  private void documentMustBeInitializedCheck() {
    logger.debug("");
    if (signedDocument == null) {
      logger.warn("Not yet implemented");
      throw new NotYetImplementedException();
    }
  }

  @Override
  public Signature sign(Signer signer) {
    logger.debug("");
    addSignerInformation(signer);
    signatureParameters.setSigningCertificate(signer.getCertificate().getX509Certificate());
    signatureParameters.setDeterministicId("S" + getSignatures().size());
    byte[] dataToSign = asicService.getDataToSign(getSigningDocument(), signatureParameters);

    return sign(signer.sign(signatureParameters.getDigestAlgorithm().getXmlId(), dataToSign));
  }

  private Signature sign(byte[] rawSignature) {
    logger.debug("");
    commonCertificateVerifier.setTrustedCertSource(getTSL());
    commonCertificateVerifier.setOcspSource(new SKOnlineOCSPSource(configuration));

    asicService = new DigiDoc4JASiCSService(commonCertificateVerifier);
    asicService.setTspSource(new OnlineTSPSource(getConfiguration().getTspSource()));
    //TODO after 4.1.0 release signing sets deteministic id to null
    String deterministicId = getSignatureParameters().getDeterministicId();
    signedDocument = asicService.signDocument(signedDocument, signatureParameters, rawSignature);

    signatureParameters.setDetachedContent(signedDocument);
    XAdESSignature xAdESSignature = getSignatureById(deterministicId);

    Signature signature = new BDocSignature(xAdESSignature);
    signatures.add(signature);

    return signature;
  }

  private DSSDocument getSigningDocument() {
    logger.debug("");
    if (signedDocument == null) {
      DataFile dataFile = getFirstDataFile();
      MimeType mimeType = MimeType.fromCode(dataFile.getMediaType());
      if (dataFile.getFileSize() > FILE_SIZE_TO_STREAM) {
        //TODO not working with big files
        signedDocument = new StreamDocument(dataFile.getStream(), dataFile.getFileName(), mimeType);
      } else
        signedDocument = new InMemoryDocument(dataFile.getBytes(), dataFile.getFileName(), mimeType);
    }
    return signedDocument;
  }

  private XAdESSignature getSignatureById(String deterministicId) {
    logger.debug("Id: " + deterministicId);
    SignedDocumentValidator validator = ASiCXMLDocumentValidator.fromDocument(signatureParameters.getDetachedContent());
    validate(validator);
    List<AdvancedSignature> signatureList = validator.getSignatures();
    for (AdvancedSignature advancedSignature : signatureList) {
      if (advancedSignature.getId().equals(deterministicId)) {
        logger.debug("Signature found");
        return (XAdESSignature) advancedSignature;
      }
    }
    SignatureNotFoundException exception = new SignatureNotFoundException();
    logger.info(exception.getMessage());
    throw exception;
  }

  private TrustedListsCertificateSource getTSL() { // TODO move to Configuration?
    logger.debug("");
    if (tslCertificateSource != null) {
      logger.debug("Using TSL cached copy");
      return tslCertificateSource;
    }
    tslCertificateSource = new TrustedListsCertificateSource();
    tslCertificateSource.setDataLoader(new CommonsDataLoader());
    tslCertificateSource.setLotlUrl(getConfiguration().getTslLocation());
    tslCertificateSource.setCheckSignature(false);
    tslCertificateSource.init();

    return tslCertificateSource;
  }

  private Configuration getConfiguration() {
    logger.debug("");
    return configuration;
  }

  @Override
  public void setConfiguration(Configuration conf) {
    logger.debug("");
    this.configuration = conf;
  }

  private void addSignerInformation(Signer signer) {
    logger.debug("");
    signatureParameters.setDigestAlgorithm(digestAlgorithm);
    BLevelParameters bLevelParameters = signatureParameters.bLevel();

    if (!(isEmpty(signer.getCity()) && isEmpty(signer.getStateOrProvince()) && isEmpty(signer.getPostalCode())
        && isEmpty(signer.getCountry()))) {
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

  /**
   * Verify ASiCS Container.
   *
   * @return list of DigiDoc4JExceptions
   */
  public List<DigiDoc4JException> verify() {
    logger.debug("");
    documentMustBeInitializedCheck();

    SignedDocumentValidator validator = ASiCXMLDocumentValidator.fromDocument(signedDocument);
    validate(validator);
    SimpleReport simpleReport = validator.getSimpleReport();

    List<DigiDoc4JException> validationErrors = new ArrayList<DigiDoc4JException>();
    List<String> signatureIds = simpleReport.getSignatureIds();
    for (String signatureId : signatureIds) {
      List<Conclusion.BasicInfo> errors = simpleReport.getErrors(signatureId);
      for (Conclusion.BasicInfo error : errors) {
        String message = error.toString();
        logger.info(message);
        validationErrors.add(new DigiDoc4JException(message));
      }
    }
    logger.debug(simpleReport.toString());

    return validationErrors;
  }

  private void validate(SignedDocumentValidator validator) {
    logger.debug("Validator: " + validator);
    CommonCertificateVerifier verifier = new CommonCertificateVerifier();
    verifier.setOcspSource(new SKOnlineOCSPSource(configuration));

    TrustedListsCertificateSource trustedCertSource = getTSL();

    verifier.setTrustedCertSource(trustedCertSource);
    validator.setCertificateVerifier(verifier);
    File policyFile = new File(getConfiguration().getValidationPolicy());
    validator.validateDocument(policyFile);
  }

  private DataFile getFirstDataFile() {
    logger.debug("");
    return (DataFile) dataFiles.values().toArray()[0];
  }

  @Override
  public List<Signature> getSignatures() {
    logger.debug("");
    return signatures;
  }

  @Override
  public DocumentType getDocumentType() {
    logger.debug("");
    return ASIC_S;
  }

  @Override
  public void setDigestAlgorithm(DigestAlgorithm algorithm) {
    logger.debug("Algorithm: " + algorithm);
    this.digestAlgorithm = forName(algorithm.name(), SHA256);
  }

  @Override
  public List<DigiDoc4JException> validate() {
    return verify();
  }

  protected SignatureParameters getSignatureParameters() {
    logger.debug("");
    return signatureParameters;
  }
}






