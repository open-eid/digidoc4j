package org.digidoc4j;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.parameter.BLevelParameters;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.*;
import eu.europa.ec.markt.dss.signature.asic.BDOCService;
import eu.europa.ec.markt.dss.validation102853.AdvancedSignature;
import eu.europa.ec.markt.dss.validation102853.CommonCertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.SignatureForm;
import eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.asic.ASiCXMLDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.https.DigiDoc4JDataLoader;
import eu.europa.ec.markt.dss.validation102853.loader.Protocol;
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
import org.digidoc4j.api.exceptions.OCSPRequestFailedException;
import org.digidoc4j.api.exceptions.SignatureNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static eu.europa.ec.markt.dss.DigestAlgorithm.SHA256;
import static eu.europa.ec.markt.dss.DigestAlgorithm.forName;
import static eu.europa.ec.markt.dss.parameter.BLevelParameters.SignerLocation;
import static org.apache.commons.lang.StringUtils.isEmpty;

/**
 * BDOC container implementation
 */
public class BDocContainer extends Container {

  final Logger logger = LoggerFactory.getLogger(BDocContainer.class);

  private final Map<String, DataFile> dataFiles = new HashMap<String, DataFile>();
  public static final int ONE_MB_IN_BYTES = 1048576;
  private CommonCertificateVerifier commonCertificateVerifier;
  protected DocumentSignatureService asicService;
  private SignatureParameters signatureParameters;
  protected DSSDocument signedDocument;
  private List<Signature> signatures = new ArrayList<Signature>();
  eu.europa.ec.markt.dss.DigestAlgorithm digestAlgorithm = SHA256;
  Configuration configuration = null;
  private TrustedListsCertificateSource tslCertificateSource;
  private static final MimeType BDOC_MIME_TYPE = MimeType.ASICE;

  /**
   * Create a new container object of type ASIC_E.
   */
  public BDocContainer() {
    logger.debug("");
    configuration = new Configuration();
    signatureParameters = new SignatureParameters();
    signatureParameters.setSignatureLevel(SignatureLevel.ASiC_E_BASELINE_LT);
    signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
    signatureParameters.setDigestAlgorithm(eu.europa.ec.markt.dss.DigestAlgorithm.SHA256);
    signatureParameters.aSiC().setAsicSignatureForm(SignatureForm.XAdES);
    signatureParameters.aSiC().setZipComment(true);

    commonCertificateVerifier = new CommonCertificateVerifier();
    asicService = new BDOCService(commonCertificateVerifier);

    logger.debug("New BDoc container created");
  }

  /**
   * Opens the container from a file.
   *
   * @param path container file name with path
   */
  public BDocContainer(String path) {
    this();
    logger.debug("Opens file: " + path);
    try {
      signedDocument = new FileDocument(path);
    } catch (DSSException e) {
      logger.error(e.getMessage());
      throw new DigiDoc4JException(e);
    }
    readsOpenedDocumentDetails();
  }

  /**
   * Opens container from a stream
   *
   * @param stream                      stream to read container from
   * @param actAsBigFilesSupportEnabled acts as configuration parameter
   * @see org.digidoc4j.api.Configuration#isBigFilesSupportEnabled() returns true
   */
  public BDocContainer(InputStream stream, boolean actAsBigFilesSupportEnabled) {
    this();
    logger.debug("");
    try {
      if (actAsBigFilesSupportEnabled) {
        signedDocument = new StreamDocument(stream, null, BDOC_MIME_TYPE);
      } else
        signedDocument = new InMemoryDocument(IOUtils.toByteArray(stream), null, BDOC_MIME_TYPE);
    } catch (IOException e) {
      logger.debug(e.getMessage());
      throw new DigiDoc4JException(e);
    }

    readsOpenedDocumentDetails();
  }

  private void readsOpenedDocumentDetails() {
    SignedDocumentValidator validator = ASiCXMLDocumentValidator.fromDocument(signedDocument);
    validate(validator);
    SimpleReport simpleReport = validator.getSimpleReport();

    List<DigiDoc4JException> validationErrors;
    List<AdvancedSignature> signatureList = validator.getSignatures();

    for (AdvancedSignature advancedSignature : signatureList) {
      validationErrors = new ArrayList<DigiDoc4JException>();
      List<Conclusion.BasicInfo> errors = simpleReport.getErrors(advancedSignature.getId());
      for (Conclusion.BasicInfo error : errors) {
        String errorMessage = error.toString();
        logger.info(errorMessage);
        validationErrors.add(new DigiDoc4JException(errorMessage));
      }
      signatures.add(new BDocSignature((XAdESSignature) advancedSignature, validationErrors));
    }

    DSSDocument externalContent = validator.getDetachedContent();
    dataFiles.put(externalContent.getName(), new DataFile(externalContent.getBytes(), externalContent.getName(),
        externalContent.getMimeType().getCode()));
    logger.debug("New BDoc container created");
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
    logger.warn("Not yet implemented");
    throw new NotYetImplementedException();
  }

  @Override
  public List<DataFile> getDataFiles() {
    logger.debug("");
    return new ArrayList<DataFile>(dataFiles.values());
  }

  @Override
  public DataFile getDataFile(int index) {
    logger.debug("get data file with index: " + index);
    return getDataFiles().get(index);
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
    signedDocument = ((BDOCService) asicService).createContainer(signingDocument, signedDocument);
    signatures.remove(index);
  }

  @Override
  public void save(String path) {
    logger.debug("Path: " + path);
    documentMustBeInitializedCheck();
    signedDocument.save(path);
  }

  @Override
  public void save(OutputStream out) {
    try {
      IOUtils.copyLarge(signedDocument.openStream(), out);
    } catch (IOException e) {
      throw new DigiDoc4JException(e);
    }
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

    asicService = new BDOCService(commonCertificateVerifier);
    asicService.setTspSource(new OnlineTSPSource(getConfiguration().getTspSource()));
    //TODO after 4.1.0 release signing sets deterministic id to null
    String deterministicId = getSignatureParameters().getDeterministicId();
    try {
      signedDocument = asicService.signDocument(signedDocument, signatureParameters, rawSignature);
    } catch (DSSException e) {
      logger.error(e.getMessage());
      if ("OCSP request failed".equals(e.getMessage()))
        throw new OCSPRequestFailedException();

      throw new DigiDoc4JException(e);
    }

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
      long cachedFileSizeInMB = configuration.getMaxDataFileCachedInMB();
      if (configuration.isBigFilesSupportEnabled() && dataFile.getFileSize() > cachedFileSizeInMB * ONE_MB_IN_BYTES) {
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
    tslCertificateSource.setDataLoader(new DigiDoc4JDataLoader());
    tslCertificateSource.setLotlUrl(getTslLocation());
    tslCertificateSource.setCheckSignature(false);
    tslCertificateSource.init();

    return tslCertificateSource;
  }

  String getTslLocation() {
    String urlString = getConfiguration().getTslLocation();
    if (!Protocol.isFileUrl(urlString)) return urlString;
    try {
      String filePath = new URL(urlString).getPath();
      if (!new File(filePath).exists()) {
        URL resource = getClass().getClassLoader().getResource(filePath);
        if (resource != null)
          urlString = resource.toString();
      }
    } catch (MalformedURLException e) {
      logger.warn(e.getMessage());
    }
    return urlString;
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
   * Verify BDoc Container.
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
  public Signature getSignature(int index) {
    return getSignatures().get(index);
  }

  @Override
  public DocumentType getDocumentType() {
    logger.debug("");
    return DocumentType.BDOC;
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






