package org.digidoc4j.impl;

import eu.europa.ec.markt.dss.DSSXMLUtils;
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
import eu.europa.ec.markt.dss.validation102853.https.CommonsDataLoader;
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
import org.digidoc4j.*;
import org.digidoc4j.exceptions.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import static eu.europa.ec.markt.dss.DigestAlgorithm.SHA256;
import static eu.europa.ec.markt.dss.DigestAlgorithm.forName;
import static eu.europa.ec.markt.dss.parameter.BLevelParameters.SignerLocation;
import static eu.europa.ec.markt.dss.signature.SignatureLevel.ASiC_E_BASELINE_B;
import static eu.europa.ec.markt.dss.signature.SignatureLevel.ASiC_E_BASELINE_LT;
import static eu.europa.ec.markt.dss.signature.SignatureLevel.ASiC_E_BASELINE_LTA;
import static eu.europa.ec.markt.dss.signature.SignaturePackaging.DETACHED;
import static eu.europa.ec.markt.dss.validation102853.SignatureForm.XAdES;
import static org.apache.commons.lang.StringUtils.isEmpty;
import static org.digidoc4j.Container.SignatureProfile.TS;

/**
 * BDOC container implementation
 */
public class BDocContainer extends Container {

  final Logger logger = LoggerFactory.getLogger(BDocContainer.class);

  private final Map<String, DataFile> dataFiles = new HashMap<>();
  public static final int ONE_MB_IN_BYTES = 1048576;
  private CommonCertificateVerifier commonCertificateVerifier;
  protected DocumentSignatureService asicService;
  private SignatureParameters signatureParameters;
  protected DSSDocument signedDocument;
  private List<Signature> signatures = new ArrayList<>();
  Configuration configuration = null;
  private TrustedListsCertificateSource tslCertificateSource;
  private static final MimeType BDOC_MIME_TYPE = MimeType.ASICE;

  /**
   * Create a new container object of type BDOC.
   */
  public BDocContainer() {
    logger.debug("");
    this.configuration = new Configuration();
    initASiC();

    logger.debug("New BDoc container created");
  }

  /**
   * Create a new container object of type BDOC with given configuration.
   * Configuration is immutable. You cant change already set configuration.
   *
   * @param configuration sets container configuration
   */
  public BDocContainer(Configuration configuration) {
    logger.debug("");
    initASiC();
    try {
      this.configuration = (Configuration) configuration.clone();
    } catch (CloneNotSupportedException e) {
      throw new DigiDoc4JException(e);
    }
    logger.debug("New BDoc container created");
  }

  private void initASiC() {
    signatureParameters = new SignatureParameters();
    signatureParameters.setSignatureLevel(ASiC_E_BASELINE_LT);
    signatureParameters.setSignaturePackaging(DETACHED);
    signatureParameters.setDigestAlgorithm(SHA256);
    signatureParameters.aSiC().setUnderlyingForm(XAdES);
    signatureParameters.aSiC().setZipComment(true);

    commonCertificateVerifier = new CommonCertificateVerifier();
    asicService = new ASiCService(commonCertificateVerifier);
  }

  /**
   * Opens the container from a file.
   *
   * @param path container file name with path
   */
  public BDocContainer(String path) {
    this(path, new Configuration());
  }

  /**
   * Opens container from a stream
   *
   * @param stream                      stream to read container from
   * @param actAsBigFilesSupportEnabled acts as configuration parameter
   * @see org.digidoc4j.Configuration#isBigFilesSupportEnabled() returns true
   */
  public BDocContainer(InputStream stream, boolean actAsBigFilesSupportEnabled) {
    this.configuration = new Configuration();
    initASiC();
    logger.debug("");
    try {
      if (actAsBigFilesSupportEnabled) {
        signedDocument = new StreamDocument(stream, null, BDOC_MIME_TYPE);
      } else
        signedDocument = new InMemoryDocument(IOUtils.toByteArray(stream), null, BDOC_MIME_TYPE);
    } catch (IOException e) {
      logger.error(e.getMessage());
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
    initASiC();
    logger.debug("Opens file: " + path);

    try {
      signedDocument = new FileDocument(path);
      checkMimeType(path);
    } catch (DSSException e) {
      logger.error(e.getMessage());
      throw new DigiDoc4JException(e);
    }

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
        throw new UnsupportedFormatException("Not an asic-e document. Mimetype is missing.");
      InputStream stream = zipFile.getInputStream(entry);
      mimeType = IOUtils.toString(stream);
      stream.close();
      zipFile.close();
    } catch (IOException e) {
      e.printStackTrace();
      throw new DigiDoc4JException(e);
    }

    return mimeType;
  }

  private void readsOpenedDocumentDetails() {
    logger.debug("");

    SignedDocumentValidator validator = ASiCContainerValidator.fromDocument(signedDocument);

    loadSignatures(validator);
    loadAttachments(validator);

    //TODO must be changed when extending signature is possible in sd-dss currently is possible to extend whole
    //container and it extend also all signatures
    setSignatureProfile(getSignatures().size() != 0 ? getSignature(0).getProfile() : TS);

    logger.debug("New BDoc container created");
  }

  private void loadAttachments(SignedDocumentValidator validator) {
    for (DSSDocument externalContent : validator.getDetachedContents()) {
      if (!"META-INF/manifest.xml".equals(externalContent.getName())) {
        dataFiles.put(externalContent.getName(), new DataFile(externalContent.getBytes(), externalContent.getName(),
            externalContent.getMimeType().getCode()));
      }
    }
  }

  private Map<String, SimpleReport> loadValidationResults(SignedDocumentValidator validator) {
    logger.debug("");
    Map<String, SimpleReport> simpleReports = new HashMap<>();

    Reports report = validate(validator);

    signatureParameters.setDigestAlgorithm(report.getDiagnosticData().getSignatureDigestAlgorithm());

    do {
      SimpleReport simpleReport = report.getSimpleReport();
      if (simpleReport.getSignatureIds().size() > 0)
        simpleReports.put(simpleReport.getSignatureIds().get(0), simpleReport);
      report = report.getNextReports();
    } while (report != null);
    return simpleReports;
  }

  private void loadSignatures(SignedDocumentValidator validator) {
    logger.debug("");
    Map<String, SimpleReport> simpleReports = loadValidationResults(validator);
    List<AdvancedSignature> signatureList = validator.getSignatures();

    List<DigiDoc4JException> validationErrors;
    for (AdvancedSignature advancedSignature : signatureList) {
      validationErrors = new ArrayList<>();
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

    if (signatures.size() > 0) {
      String errorMessage = "Datafiles cannot be added to an already signed container";
      logger.error(errorMessage);
      throw new DigiDoc4JException(errorMessage);
    }

    checkForDuplicateDataFile(path);

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

  private void checkForDuplicateDataFile(String path) {
    String fileName = new File(path).getName();
    for (String key : dataFiles.keySet()) {
      if (dataFiles.get(key).getName().equals(fileName)) {
        String errorMessage = "Data file " + fileName + " already exists";
        logger.error(errorMessage);
        throw new DigiDoc4JException(errorMessage);
      }
    }
  }

  @Override
  public void addDataFile(InputStream is, String fileName, String mimeType) {
    logger.debug("File name: " + fileName + ", mime type: " + mimeType);
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
    return new ArrayList<>(dataFiles.values());
  }

  @Override
  public DataFile getDataFile(int index) {
    logger.debug("get data file with index: " + index);
    return getDataFiles().get(index);
  }

  @Override
  public void removeDataFile(String fileName) {
    logger.debug("File name: " + fileName);

    if (signatures.size() > 0) {
      String errorMessage = "Datafiles cannot be removed from an already signed container";
      logger.error(errorMessage);
      throw new DigiDoc4JException(errorMessage);
    }

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

    signedDocument = null;
    do {
      signatureParameters.aSiC().setSignatureFileName(getSignatureFileName(signature));
      signedDocument = ((ASiCService) asicService).buildASiCContainer(signingDocument, signedDocument,
          signatureParameters, createBareDocument(signature));
      signature = signature.getNextDocument();
    } while (signature != null);

    signatures.remove(index);
  }

  private DSSDocument createBareDocument(DSSDocument signature) {
    if (signature.getName() == null) return signature;
    Document root = DSSXMLUtils.buildDOM(signature);
    final Element signatureEl = (Element) root.getDocumentElement().getFirstChild();
    return new InMemoryDocument(DSSXMLUtils.serializeNode(signatureEl));
  }

  private String getSignatureFileName(DSSDocument signature) {
    if (signature.getName() == null)
      return "signatures0.xml";
    return signature.getName().substring(signature.getName().lastIndexOf('/') + 1);
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
      logger.error(e.getMessage());
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
  public Signature sign(Signer signer, String signatureId) {
    logger.debug("");

    byte[] dataToSign = prepareSigning(signer.getSignatureProductionPlace(), signer.getSignerRoles(), signatureId,
        signer.getCertificate());

    byte[] signature = signer.sign(this, dataToSign);
    return signRaw(signature);
  }

  /**
   * Return info that needs to be signed
   *
   * @param productionPlace   Production place info
   * @param roles             List of roles
   * @param signatureId       signature id for signing
   * @param signerCertificate X509 Certificate of signer
   * @return byte array with info that needs to be signed
   */
  private byte[] prepareSigning(SignatureProductionPlace productionPlace, List<String> roles, String signatureId,
                                X509Certificate signerCertificate) {
    addSignerInformation(productionPlace, roles);

    signatureParameters.clearCertificateChain();
    signatureParameters.setDeterministicId(signatureId);
    signatureParameters.aSiC().setSignatureFileName("signatures" + signatures.size() + ".xml");
    signatureParameters.setSigningCertificate(signerCertificate);

    DSSDocument attachment = getAttachment();
    signatureParameters.setDetachedContent(attachment);

    return asicService.getDataToSign(attachment, signatureParameters);
  }

  @Override
  public Signature sign(Signer signer) {
    return sign(signer, "S" + getSignatures().size());
  }

  private Signature signRaw(byte[] rawSignature) {
    logger.debug("");

    commonCertificateVerifier.setTrustedCertSource(getTSL());
    commonCertificateVerifier.setOcspSource(new SKOnlineOCSPSource(configuration));
    asicService.setTspSource(new OnlineTSPSource(getConfiguration().getTspSource()));

    String deterministicId = getSignatureParameters().getDeterministicId();

    try {
      signedDocument = asicService.signDocument(getSigningDocument(), signatureParameters, rawSignature);
    } catch (DSSException e) {
      logger.error(e.getMessage());
      if ("OCSP request failed".equals(e.getMessage()))
        throw new OCSPRequestFailedException();
      throw new DigiDoc4JException(e);
    }

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

    if (dataFiles.size() == 0) {
      String errorMessage = "Container does not contain any attachments";
      logger.error(errorMessage);
      throw new DigiDoc4JException(errorMessage);
    }
    Iterator<String> iterator = dataFiles.keySet().iterator();
    attachment = getDssDocumentFromDataFile(dataFiles.get(iterator.next()));
    while (iterator.hasNext()) {
      String fileName = iterator.next();
      attachment.setNextDocument(getDssDocumentFromDataFile(dataFiles.get(fileName)));
    }

    return attachment;
  }

  private DSSDocument getDssDocumentFromDataFile(DataFile dataFile) {
    DSSDocument attachment;
    MimeType mimeType = MimeType.fromCode(dataFile.getMediaType());
    long cachedFileSizeInMB = configuration.getMaxDataFileCachedInMB();
    if (configuration.isBigFilesSupportEnabled() && dataFile.getFileSize() > cachedFileSizeInMB * ONE_MB_IN_BYTES) {
      attachment = new StreamDocument(dataFile.getStream(), dataFile.getName(), mimeType);
    } else {
      attachment = new InMemoryDocument(dataFile.getBytes(), dataFile.getName(), mimeType);
    }
    return attachment;
  }

  private XAdESSignature getSignatureById(String deterministicId) {
    logger.debug("Id: " + deterministicId);
    SignedDocumentValidator validator = ASiCXMLDocumentValidator.fromDocument(signedDocument);
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

    String tslLocation = getTslLocation();
    if (Protocol.isHttpUrl(tslLocation)) {
      tslCertificateSource.setDataLoader(new FileCacheDataLoader()); //TODO test is missing
    } else {
      tslCertificateSource.setDataLoader(new CommonsDataLoader());
    }

    tslCertificateSource.setLotlUrl(tslLocation);
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

  private void addSignerInformation(SignatureProductionPlace signatureProductionPlace, List<String> signerRoles) {
    logger.debug("");
    BLevelParameters bLevelParameters = signatureParameters.bLevel();

    if (!(isEmpty(signatureProductionPlace.getCity()) && isEmpty(signatureProductionPlace.getStateOrProvince())
        && isEmpty(signatureProductionPlace.getPostalCode())
        && isEmpty(signatureProductionPlace.getCountry()))) {

      SignerLocation signerLocation = new SignerLocation();

      if (!isEmpty(signatureProductionPlace.getCity()))
        signerLocation.setCity(signatureProductionPlace.getCity());
      if (!isEmpty(signatureProductionPlace.getStateOrProvince()))
        signerLocation.setStateOrProvince(signatureProductionPlace.getStateOrProvince());
      if (!isEmpty(signatureProductionPlace.getPostalCode()))
        signerLocation.setPostalCode(signatureProductionPlace.getPostalCode());
      if (!isEmpty(signatureProductionPlace.getCountry()))
        signerLocation.setCountry(signatureProductionPlace.getCountry());
      bLevelParameters.setSignerLocation(signerLocation);
    }
    for (String signerRole : signerRoles) {
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
    signatureParameters.setDigestAlgorithm(forName(algorithm.name(), SHA256));
  }

  @Override
  public DigestAlgorithm getDigestAlgorithm() {
    return DigestAlgorithm.valueOf(signatureParameters.getDigestAlgorithm().getName());
  }

  @Override
  public ValidationResult validate() {
    return verify();
  }

  private void extend(SignatureLevel signatureLevel) {
    if (signatureLevel == signatureParameters.getSignatureLevel())
      throw new DigiDoc4JException("It is no possible to extend signature to same level");

    commonCertificateVerifier.setTrustedCertSource(getTSL());
    commonCertificateVerifier.setOcspSource(new SKOnlineOCSPSource(configuration));
    asicService.setTspSource(new OnlineTSPSource(getConfiguration().getTspSource()));

    signatureParameters.setSignatureLevel(signatureLevel);
    signedDocument = asicService.extendDocument(signedDocument, signatureParameters);

    signatures = new ArrayList<>();
    SignedDocumentValidator validator = ASiCXMLDocumentValidator.fromDocument(signedDocument);
    validate(validator);

    List<AdvancedSignature> signatureList = validator.getSignatures();
    for (AdvancedSignature advancedSignature : signatureList) {
      signatures.add(new BDocSignature((XAdESSignature) advancedSignature));
    }
  }

  @Override
  public String getVersion() {
    return null;
  }

  @Override
  public void extendTo(SignatureProfile profile) {
    switch (profile) {
      case TS:
        extend(ASiC_E_BASELINE_LT);
        break;
      case TSA:
        extend(ASiC_E_BASELINE_LTA);
        break;
      default:
        throw new NotYetImplementedException();
    }
  }

  @Override
  public void setSignatureProfile(SignatureProfile profile) {
    switch (profile) {
      case TM:
        throw new NotYetImplementedException();
      case BES:
        signatureParameters.setSignatureLevel(ASiC_E_BASELINE_B);
        break;
      case TSA:
        signatureParameters.setSignatureLevel(ASiC_E_BASELINE_LTA);
        break;
      default:
        signatureParameters.setSignatureLevel(ASiC_E_BASELINE_LT);
    }
  }

  protected SignatureParameters getSignatureParameters() {
    logger.debug("");
    return signatureParameters;
  }
}
