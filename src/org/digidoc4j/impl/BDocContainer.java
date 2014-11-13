package org.digidoc4j.impl;

import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.parameter.BLevelParameters;
import eu.europa.ec.markt.dss.signature.*;
import eu.europa.ec.markt.dss.signature.asic.ASiCService;
import eu.europa.ec.markt.dss.validation102853.AdvancedSignature;
import eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.asic.ASiCContainerValidator;
import eu.europa.ec.markt.dss.validation102853.asic.ASiCXMLDocumentValidator;
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
import org.digidoc4j.utils.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import static eu.europa.ec.markt.dss.DigestAlgorithm.SHA256;
import static eu.europa.ec.markt.dss.DigestAlgorithm.forName;
import static eu.europa.ec.markt.dss.parameter.BLevelParameters.SignerLocation;
import static eu.europa.ec.markt.dss.signature.SignatureLevel.*;
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
  private SKCommonCertificateVerifier commonCertificateVerifier;
  protected DocumentSignatureService asicService;
  private eu.europa.ec.markt.dss.parameter.SignatureParameters dssSignatureParameters;
  private SignatureParameters signatureParameters = new SignatureParameters();
  protected DSSDocument signedDocument;
  private List<Signature> signatures = new ArrayList<>();
  Configuration configuration = null;
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

  @Override
  public SignedInfo prepareSigning(X509Certificate signerCert) {
    String signatureId = signatureParameters.getSignatureId();
    byte[] signedInfo = getDataToSign(signatureId != null ? signatureId : "S" + getSignatures().size(), signerCert);

    return new SignedInfo(signedInfo, signatureParameters.getDigestAlgorithm());
  }

  @Override
  public String getSignatureProfile() {
    return dssSignatureParameters.getSignatureLevel().name();
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
    configuration.getTSL();
    this.configuration = configuration.copy();
    logger.debug("New BDoc container created");
  }


  @Override
  public void setSignatureParameters(SignatureParameters signatureParameters) {
    this.signatureParameters = signatureParameters.copy();

    setDigestAlgorithm();

    addSignerInformation();
  }

  private void setDigestAlgorithm() {
    if (signatureParameters.getDigestAlgorithm() == null) {
      signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
    }
    dssSignatureParameters.setDigestAlgorithm(forName(signatureParameters.getDigestAlgorithm().name(), SHA256));
  }

  @Override
  public DigestAlgorithm getDigestAlgorithm() {
    return signatureParameters.getDigestAlgorithm();
  }

  private void initASiC() {
    dssSignatureParameters = new eu.europa.ec.markt.dss.parameter.SignatureParameters();
    dssSignatureParameters.setSignatureLevel(ASiC_E_BASELINE_LT);
    dssSignatureParameters.setSignaturePackaging(DETACHED);
    dssSignatureParameters.setDigestAlgorithm(SHA256);
    signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
    dssSignatureParameters.aSiC().setUnderlyingForm(XAdES);
    dssSignatureParameters.aSiC().setZipComment(true);

    commonCertificateVerifier = new SKCommonCertificateVerifier();
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
      signedDocument.setMimeType(MimeType.ASICE);
      checkMimeType(path);
    } catch (DSSException e) {
      logger.error(e.getMessage());
      throw new DigiDoc4JException(e);
    }

    configuration.getTSL();
    this.configuration = configuration.copy();
    readsOpenedDocumentDetails();
  }

  private void checkMimeType(String path) {
    String bdocMimeTypeFromZip = getBdocMimeTypeFromZip(path).trim();
    try {
      if (!MimeType.ASICE.equals(MimeType.fromMimeTypeString(bdocMimeTypeFromZip))) {
        throw new UnsupportedFormatException(bdocMimeTypeFromZip);
      }
    } catch (DSSException e) {
      throw new UnsupportedFormatException(bdocMimeTypeFromZip);
    }
  }

  private String getBdocMimeTypeFromZip(String path) {
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
    eu.europa.ec.markt.dss.DigestAlgorithm digestAlgorithm = dssSignatureParameters.getDigestAlgorithm();
    if (digestAlgorithm != null) {
      signatureParameters.setDigestAlgorithm(DigestAlgorithm.valueOf(digestAlgorithm.getName()));
    } else {
      signatureParameters.setDigestAlgorithm(null);
    }

    logger.debug("New BDoc container created");
  }

  private void loadAttachments(SignedDocumentValidator validator) {
    for (DSSDocument externalContent : validator.getDetachedContents()) {
      if (!"mimetype".equals(externalContent.getName()) && !"META-INF/manifest.xml".equals(externalContent.getName())) {
        dataFiles.put(externalContent.getName(), new DataFile(externalContent.getBytes(), externalContent.getName(),
            externalContent.getMimeType().getMimeTypeString()));
      }
    }
  }

  private Map<String, SimpleReport> loadValidationResults(SignedDocumentValidator validator) {
    logger.debug("");
    Map<String, SimpleReport> simpleReports = new HashMap<>();

    Reports report = validate(validator);

    dssSignatureParameters.setDigestAlgorithm(report.getDiagnosticData().getSignatureDigestAlgorithm());

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
      String reportSignatureId = advancedSignature.getId();
      SimpleReport simpleReport = getSimpleReport(simpleReports, reportSignatureId);
      if (simpleReport != null) {
        for (Conclusion.BasicInfo error : simpleReport.getErrors(reportSignatureId)) {
          String errorMessage = error.toString();
          logger.info(errorMessage);
          validationErrors.add(new DigiDoc4JException(errorMessage));
        }
      }
      signatures.add(new BDocSignature((XAdESSignature) advancedSignature, validationErrors));
    }
  }

  private SimpleReport getSimpleReport(Map<String, SimpleReport> simpleReports, String fromSignatureId) {
    logger.debug("signature id = " + fromSignatureId);
    SimpleReport simpleReport = simpleReports.get(fromSignatureId);
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
        InputStream is = Files.newInputStream(Paths.get(path));
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
    dssSignatureParameters.setDetachedContent(signingDocument);

    signedDocument = null;
    do {
      dssSignatureParameters.aSiC().setSignatureFileName(getSignatureFileName(signature));
      signedDocument = ((ASiCService) asicService).buildASiCContainer(signingDocument, signedDocument,
          dssSignatureParameters, createBareDocument(signature));
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
  public Signature sign(Signer signer) {
    logger.debug("");
    byte[] dataToSign;
    String signatureId = signatureParameters.getSignatureId();
    dataToSign = getDataToSign(signatureId != null ? signatureId : "S" + getSignatures().size(),
        signer.getCertificate());

    byte[] signature = signer.sign(this, dataToSign);
    return signRaw(signature);
  }

  private byte[] getDataToSign(String setSignatureId, X509Certificate signerCertificate) {
    dssSignatureParameters.clearCertificateChain();
    dssSignatureParameters.setDeterministicId(setSignatureId);
    dssSignatureParameters.aSiC().setSignatureFileName("signatures" + signatures.size() + ".xml");
    dssSignatureParameters.setSigningCertificate(signerCertificate);

    DSSDocument attachment = getAttachment();
    dssSignatureParameters.setDetachedContent(attachment);

    return asicService.getDataToSign(attachment, dssSignatureParameters);
  }

  @Override
  public Signature signRaw(byte[] rawSignature) {
    logger.debug("");

    commonCertificateVerifier.setTrustedCertSource(configuration.getTSL());
    SKOnlineOCSPSource ocspSource = new SKOnlineOCSPSource(configuration);
    ocspSource.setUserAgent(Helper.createUserAgent(this));
    commonCertificateVerifier.setOcspSource(ocspSource);
    asicService.setTspSource(new OnlineTSPSource(getConfiguration().getTspSource()));

    String deterministicId = getDssSignatureParameters().getDeterministicId();

    try {
      signedDocument = asicService.signDocument(getSigningDocument(), dssSignatureParameters, rawSignature);
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
    MimeType mimeType = MimeType.fromMimeTypeString(dataFile.getMediaType());
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

  private Configuration getConfiguration() {
    logger.debug("");
    return configuration;
  }

  private void addSignerInformation() {
    logger.debug("");
    SignatureProductionPlace signatureProductionPlace = signatureParameters.getProductionPlace();
    List<String> signerRoles = signatureParameters.getRoles();

    BLevelParameters bLevelParameters = dssSignatureParameters.bLevel();

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
    commonCertificateVerifier.setOcspSource(null);

    TrustedListsCertificateSource trustedCertSource = configuration.getTSL();

    commonCertificateVerifier.setTrustedCertSource(trustedCertSource);
    validator.setCertificateVerifier(commonCertificateVerifier);

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
  public ValidationResult validate() {
    return verify();
  }

  private void extend(SignatureLevel signatureLevel) {
    if (signatureLevel == dssSignatureParameters.getSignatureLevel())
      throw new DigiDoc4JException("It is not possible to extend the signature to the same level");

    commonCertificateVerifier.setTrustedCertSource(configuration.getTSL());
    SKOnlineOCSPSource ocspSource = new SKOnlineOCSPSource(configuration);
    ocspSource.setUserAgent(Helper.createUserAgent(this));
    commonCertificateVerifier.setOcspSource(ocspSource);
    asicService.setTspSource(new OnlineTSPSource(getConfiguration().getTspSource()));

    dssSignatureParameters.setSignatureLevel(signatureLevel);

    DSSDocument extendedDocument = asicService.extendDocument(signedDocument, dssSignatureParameters);
    signedDocument = new InMemoryDocument(extendedDocument.getBytes(),
        signedDocument.getName(), signedDocument.getMimeType());

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
        dssSignatureParameters.setSignatureLevel(ASiC_E_BASELINE_B);
        break;
      case TSA:
        dssSignatureParameters.setSignatureLevel(ASiC_E_BASELINE_LTA);
        break;
      default:
        dssSignatureParameters.setSignatureLevel(ASiC_E_BASELINE_LT);
    }
  }

  protected eu.europa.ec.markt.dss.parameter.SignatureParameters getDssSignatureParameters() {
    logger.debug("");
    return dssSignatureParameters;
  }
}
