package org.digidoc4j;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.parameter.BLevelParameters;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.*;
import eu.europa.ec.markt.dss.signature.asic.ASiCService;
import eu.europa.ec.markt.dss.validation102853.AdvancedSignature;
import eu.europa.ec.markt.dss.validation102853.CommonCertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.asic.ASiCContainerValidator;
import eu.europa.ec.markt.dss.validation102853.asic.ASiCXMLDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.https.FileCacheDataLoader;
import eu.europa.ec.markt.dss.validation102853.loader.Protocol;
import eu.europa.ec.markt.dss.validation102853.ocsp.SKOnlineOCSPSource;
import eu.europa.ec.markt.dss.validation102853.report.Conclusion;
import eu.europa.ec.markt.dss.validation102853.report.Reports;
import eu.europa.ec.markt.dss.validation102853.report.SimpleReport;
import eu.europa.ec.markt.dss.validation102853.tsl.TrustedListsCertificateSource;
import eu.europa.ec.markt.dss.validation102853.tsp.OnlineTSPSource;
import eu.europa.ec.markt.dss.validation102853.xades.XAdESSignature;
import org.apache.commons.io.IOUtils;
import org.digidoc4j.api.*;
import org.digidoc4j.api.exceptions.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import static eu.europa.ec.markt.dss.DigestAlgorithm.SHA256;
import static eu.europa.ec.markt.dss.DigestAlgorithm.forName;
import static eu.europa.ec.markt.dss.parameter.BLevelParameters.SignerLocation;
import static eu.europa.ec.markt.dss.signature.SignatureLevel.ASiC_E_BASELINE_LT;
import static eu.europa.ec.markt.dss.signature.SignaturePackaging.DETACHED;
import static eu.europa.ec.markt.dss.validation102853.SignatureForm.XAdES;
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
    configuration.loadConfiguration("digidoc4j.yaml");
    signatureParameters = new SignatureParameters();
    signatureParameters.setSignatureLevel(ASiC_E_BASELINE_LT);
    signatureParameters.setSignaturePackaging(DETACHED);
    signatureParameters.setDigestAlgorithm(SHA256);
    signatureParameters.aSiC().setUnderlyingForm(XAdES);
    signatureParameters.aSiC().setZipComment(true);

    commonCertificateVerifier = new CommonCertificateVerifier();
    asicService = new ASiCService(commonCertificateVerifier);

    logger.debug("New BDoc container created");
  }

  /**
   * Opens the container from a file.
   *
   * @param path container file name with path
   */
  public BDocContainer(String path) {
    this(path, null);
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

  /**
   * Opens container from a file with specified configuration settings
   *
   * @param path          container file name with path
   * @param configuration configuration settings
   */
  public BDocContainer(String path, Configuration configuration) {
    this();
    logger.debug("Opens file: " + path);

    try {

      signedDocument = new FileDocument(path);
      checkMimeType(path);

    } catch (DSSException e) {
      logger.error(e.getMessage());
      throw new DigiDoc4JException(e);
    }

    if (configuration != null)
      this.configuration = configuration;

    readsOpenedDocumentDetails();
  }

  private void checkMimeType(String path) {
    String bdocMimeTypeFromZIp = getBdocMimeTypeFromZIp(path).trim();
    if (!MimeType.ASICE.equals(MimeType.fromCode(bdocMimeTypeFromZIp))) {
      throw new UnsupportedFormatException(bdocMimeTypeFromZIp);
    }
  }

  private String getBdocMimeTypeFromZIp(String path) {
    String mimeType;
    try {
      ZipFile zipFile = new ZipFile(path);
      ZipEntry entry = zipFile.getEntry("mimetype");
      if (entry == null)
        throw new UnsupportedFormatException("Not asic-e document. Mimetype is missing.");
      InputStream stream = zipFile.getInputStream(entry);
      mimeType = IOUtils.toString(stream);
      stream.close();
      zipFile.close();
    } catch (IOException e) {
      e.printStackTrace();
      throw new UnsupportedFormatException("Not asic-e document");
    }

    return mimeType;
  }

  private void readsOpenedDocumentDetails() {
    logger.debug("");

    SignedDocumentValidator validator = ASiCContainerValidator.fromDocument(signedDocument);

    Map<String, SimpleReport> simpleReports = loadValidationResults(validator);
    loadSignatures(simpleReports, validator.getSignatures());

    List<DSSDocument> detachedContents = validator.getDetachedContents();
    DSSDocument externalContent = detachedContents.get(0);
    dataFiles.put(externalContent.getName(), new DataFile(externalContent.getBytes(), externalContent.getName(),
        externalContent.getMimeType().getCode()));

    logger.debug("New BDoc container created");
  }

  private Map<String, SimpleReport> loadValidationResults(SignedDocumentValidator validator) {
    logger.debug("");
    Map<String, SimpleReport> simpleReports = new HashMap<String, SimpleReport>();

    Reports report = validate(validator);
    do {
      SimpleReport simpleReport = report.getSimpleReport();
      if(simpleReport.getSignatureIds().size() > 0)
        simpleReports.put(simpleReport.getSignatureIds().get(0), simpleReport);
      report = report.getNextReports();
    } while (report != null);
    return simpleReports;
  }

  private void loadSignatures(Map<String, SimpleReport> simpleReports, List<AdvancedSignature> signatureList) {
    logger.debug("");
    List<DigiDoc4JException> validationErrors;
    for (AdvancedSignature advancedSignature : signatureList) {
      validationErrors = new ArrayList<DigiDoc4JException>();
      String signatureId = advancedSignature.getId();
      SimpleReport simpleReport = getSimpleReport(simpleReports, signatureId);
      if (simpleReport != null) {
        for (Conclusion.BasicInfo error : simpleReport.getErrors(signatureId)) {
          String errorMessage = error.toString();
          logger.info(errorMessage);
          validationErrors.add(new DigiDoc4JException(errorMessage));
        }
      }
      signatures.add(new BDocSignature((XAdESSignature) advancedSignature, validationErrors));
    }
  }

  private SimpleReport getSimpleReport(Map<String, SimpleReport> simpleReports, String signatureId) {
    logger.debug("signature id = " + signatureId);
    SimpleReport simpleReport = simpleReports.get(signatureId);
    if (simpleReport != null && simpleReports.size() == 1) {
      return simpleReports.values().iterator().next();
    }
    return simpleReport;
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
    if (canAddDataFile()) {
      try {
        long cachedFileSizeInBytes = configuration.getMaxDataFileCachedInBytes();
        if (configuration.isBigFilesSupportEnabled() && new File(path).length() > cachedFileSizeInBytes) {
          dataFiles.put(path, new DataFile(path, mimeType));
        } else {
          FileInputStream is = new FileInputStream(path);
          dataFiles.put(path, new DataFile(IOUtils.toByteArray(is), path, mimeType));
          is.close();
        }
      } catch (IOException e) {
        logger.error(e.getMessage());
        throw new DigiDoc4JException(e);
      }
    }
  }

  @Override
  public void addDataFile(InputStream is, String fileName, String mimeType) {
    logger.debug("File name: " + fileName + ", mime type: " + mimeType);
    if (canAddDataFile()) {
      try {
        if (configuration.isBigFilesSupportEnabled()) {
          dataFiles.put(fileName, new DataFile(is, fileName, mimeType));
        } else {
          dataFiles.put(fileName, new DataFile(IOUtils.toByteArray(is), fileName, mimeType));
        }
      } catch (IOException e) {
        logger.error(e.getMessage());
        throw new DigiDoc4JException(e);
      }
    }
  }

  private boolean canAddDataFile() {
    if (dataFiles.size() >= 1) {
      DigiDoc4JException exception = new DigiDoc4JException("ASiCS supports only one attachment");
      logger.error(exception.getMessage());
      throw exception;
    }
    return true;
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
    DSSDocument signingDocument = getAttachment();
    DSSDocument signature = validator.removeSignature("S" + index);
    signatureParameters.setDetachedContent(signingDocument);
    signedDocument = ((ASiCService)asicService).buildASiCContainer(signingDocument, signatureParameters, signature);
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
    String signatureId = "S" + getSignatures().size();
    signatureParameters.setDeterministicId(signatureId);
    signatureParameters.aSiC().setSignatureFileName("signature" + signatureId.toLowerCase() + ".xml");

    byte[] dataToSign = asicService.getDataToSign(getAttachment(), signatureParameters);

    return sign(signer.sign(signatureParameters.getDigestAlgorithm().getXmlId(), dataToSign));
  }

  private Signature sign(byte[] rawSignature) {
    logger.debug("");
    commonCertificateVerifier.setTrustedCertSource(getTSL());
    commonCertificateVerifier.setOcspSource(new SKOnlineOCSPSource(configuration));

    asicService.setTspSource(new OnlineTSPSource(getConfiguration().getTspSource()));
    String deterministicId = getSignatureParameters().getDeterministicId();
    signatureParameters.setDetachedContent(getAttachment());

    try {
      signedDocument = asicService.signDocument(getSigningDocument(), signatureParameters, rawSignature);
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
      signedDocument = getAttachment();
    }
    return signedDocument;
  }

  private DSSDocument getAttachment() {
    DSSDocument attachment;
    DataFile dataFile = getFirstDataFile();
    MimeType mimeType = MimeType.fromCode(dataFile.getMediaType());
    long cachedFileSizeInMB = configuration.getMaxDataFileCachedInMB();
    if (configuration.isBigFilesSupportEnabled() && dataFile.getFileSize() > cachedFileSizeInMB * ONE_MB_IN_BYTES) {
      attachment = new StreamDocument(dataFile.getStream(), dataFile.getFileName(), mimeType);
    } else {
      attachment = new InMemoryDocument(dataFile.getBytes(), dataFile.getFileName(), mimeType);
    }
    return attachment;
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

    tslCertificateSource.setDataLoader(new FileCacheDataLoader());

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
   * @return result of the verification
   */
  public ValidationResult verify() {
    logger.debug("");
    documentMustBeInitializedCheck();

    SignedDocumentValidator validator = ASiCXMLDocumentValidator.fromDocument(signedDocument);

    return new ValidationResultForBDoc(validate(validator));
  }

  private Reports validate(SignedDocumentValidator validator) {
    logger.debug("Validator: " + validator);
    CommonCertificateVerifier verifier = new CommonCertificateVerifier();
    verifier.setOcspSource(new SKOnlineOCSPSource(configuration));

    TrustedListsCertificateSource trustedCertSource = getTSL();

    verifier.setTrustedCertSource(trustedCertSource);
    validator.setCertificateVerifier(verifier);

    return validator.validateDocument(getValidationPolicyAsStream(getConfiguration().getValidationPolicy()));
  }

  private InputStream getValidationPolicyAsStream(String policyFile) {

    if (Files.exists(Paths.get(policyFile))) {
      try {
        return new FileInputStream(policyFile);
      } catch (FileNotFoundException ignore) {
        logger.warn(ignore.getMessage());
      }
    }

    return getClass().getClassLoader().getResourceAsStream(policyFile);
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
  public ValidationResult validate() {
    return verify();
  }

  protected SignatureParameters getSignatureParameters() {
    logger.debug("");
    return signatureParameters;
  }
}






