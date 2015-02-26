/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl;

import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.parameter.BLevelParameters;
import eu.europa.ec.markt.dss.signature.*;
import eu.europa.ec.markt.dss.signature.asic.ASiCService;
import eu.europa.ec.markt.dss.validation102853.AdvancedSignature;
import eu.europa.ec.markt.dss.validation102853.SignaturePolicy;
import eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.asic.ASiCContainerValidator;
import eu.europa.ec.markt.dss.validation102853.asic.ASiCXMLDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.ocsp.BDocTMOcspSource;
import eu.europa.ec.markt.dss.validation102853.ocsp.BDocTSOcspSource;
import eu.europa.ec.markt.dss.validation102853.ocsp.SKOnlineOCSPSource;
import eu.europa.ec.markt.dss.validation102853.report.Conclusion;
import eu.europa.ec.markt.dss.validation102853.report.Reports;
import eu.europa.ec.markt.dss.validation102853.report.SimpleReport;
import eu.europa.ec.markt.dss.validation102853.rules.MessageTag;
import eu.europa.ec.markt.dss.validation102853.tsl.TrustedListsCertificateSource;
import eu.europa.ec.markt.dss.validation102853.tsp.OnlineTSPSource;
import eu.europa.ec.markt.dss.validation102853.xades.XAdESSignature;
import eu.europa.ec.markt.dss.validation102853.xades.XPathQueryHolder;
import org.apache.commons.io.IOUtils;
import org.digidoc4j.*;
import org.digidoc4j.exceptions.*;
import org.digidoc4j.utils.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.*;
import java.net.URI;
import java.net.URISyntaxException;
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
import static java.util.Arrays.asList;
import static org.apache.commons.codec.binary.Base64.decodeBase64;
import static org.apache.commons.lang.StringUtils.isBlank;
import static org.apache.commons.lang.StringUtils.isEmpty;
import static org.digidoc4j.Container.SignatureProfile.LT;

/**
 * BDOC container implementation
 */
public class BDocContainer extends Container {
  private static final String TM_POLICY = "urn:oid:1.3.6.1.4.1.10015.1000.3.2.1";
  private static final String OIDAS_URN = "OIDAsURN";
  private static final String XADES_SIGNED_PROPERTIES = "http://uri.etsi.org/01903#SignedProperties";
  public static final int ONE_MB_IN_BYTES = 1048576;

  final Logger logger = LoggerFactory.getLogger(BDocContainer.class);

  private final Map<String, DataFile> dataFiles = new HashMap<>();
  private Map<String, List<DigiDoc4JException>> additionalVerificationErrors = new HashMap<>();
  private SKCommonCertificateVerifier commonCertificateVerifier;
  protected DocumentSignatureService asicService;
  private eu.europa.ec.markt.dss.parameter.SignatureParameters dssSignatureParameters;
  private SignatureParameters signatureParameters = new SignatureParameters();
  protected DSSDocument signedDocument;
  private List<Signature> signatures = new ArrayList<>();
  Configuration configuration = null;
  private static final MimeType BDOC_MIME_TYPE = MimeType.ASICE;
  private transient Reports validationReport;
  private boolean isTimeMark = false;

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
    logger.debug("");
    String signatureId = signatureParameters.getSignatureId();
    byte[] signedInfo = getDataToSign(signatureId != null ? signatureId : "S" + getSignatures().size(), signerCert);

    return new SignedInfo(signedInfo, signatureParameters.getDigestAlgorithm());
  }

  @Override
  public String getSignatureProfile() {
    logger.debug("");
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
    logger.debug("");
    this.signatureParameters = signatureParameters.copy();

    setDigestAlgorithm();

    setEncryptionAlgorithm();
    addSignerInformation();
  }

  private void setEncryptionAlgorithm() {
    logger.debug("");
    if (signatureParameters.getEncryptionAlgorithm() == EncryptionAlgorithm.ECDSA) {
      dssSignatureParameters.setEncryptionAlgorithm(eu.europa.ec.markt.dss.EncryptionAlgorithm.ECDSA);
    }
  }

  private void setDigestAlgorithm() {
    logger.debug("");
    if (signatureParameters.getDigestAlgorithm() == null) {
      signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
    }
    dssSignatureParameters.setDigestAlgorithm(forName(signatureParameters.getDigestAlgorithm().name(), SHA256));
  }

  @Override
  public DigestAlgorithm getDigestAlgorithm() {
    DigestAlgorithm digestAlgorithm = signatureParameters.getDigestAlgorithm();
    logger.debug("");
    return digestAlgorithm;
  }

  private void initASiC() {
    logger.debug("");
    dssSignatureParameters = new eu.europa.ec.markt.dss.parameter.SignatureParameters();
    dssSignatureParameters.setSignatureLevel(ASiC_E_BASELINE_LT);
    dssSignatureParameters.setSignaturePackaging(DETACHED);
    dssSignatureParameters.setDigestAlgorithm(SHA256);
    signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
    dssSignatureParameters.aSiC().setUnderlyingForm(XAdES);
    dssSignatureParameters.aSiC().setZipComment(Helper.createUserAgent(this));
    dssSignatureParameters.bLevel().setSigningCertificateDigestMethod(eu.europa.ec.markt.dss.DigestAlgorithm.SHA256);
    //dssSignatureParameters.setSignedInfoCanonicalizationMethod(Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS);

    commonCertificateVerifier = new SKCommonCertificateVerifier();
    commonCertificateVerifier.setCrlSource(null);
    asicService = new ASiCService(commonCertificateVerifier);
  }

  private void addSignaturePolicy() {
    logger.debug("");
    BLevelParameters.Policy signaturePolicy = new BLevelParameters.Policy();
    signaturePolicy.setId("urn:oid:1.3.6.1.4.1.10015.1000.3.2.1");
    signaturePolicy.setDigestValue(decodeBase64("3Tl1oILSvOAWomdI9VeWV6IA/32eSXRUri9kPEz1IVs="));
    signaturePolicy.setDigestAlgorithm(SHA256);
    try {
      URI uri = new URI("https://www.sk.ee/repository/bdoc-spec21.pdf");
      List<URI> qualifiers = asList(uri);
      signaturePolicy.setSigPolicyQualifiers(qualifiers);
    } catch (URISyntaxException ignore) {
    }
    dssSignatureParameters.bLevel().setSignaturePolicy(signaturePolicy);
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
    this(stream, actAsBigFilesSupportEnabled, new Configuration());
  }

  public BDocContainer(InputStream stream, boolean actAsBigFilesSupportEnabled, Configuration configuration) {
    logger.debug("");
    this.configuration = configuration;
    initASiC();
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
    logger.debug("Opens file: " + path);
    initASiC();

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
    logger.debug("Check mime type for " + path);
    String bdocMimeTypeFromZip = getBdocMimeTypeFromZip(path).trim();
    try {
      if (!MimeType.ASICE.equals(MimeType.fromMimeTypeString(bdocMimeTypeFromZip))) {
        throw new UnsupportedFormatException(bdocMimeTypeFromZip);
      }
    } catch (DSSException e) {
      logger.error("Unsupported format: " + bdocMimeTypeFromZip);
      throw new UnsupportedFormatException(bdocMimeTypeFromZip);
    }
  }

  private String getBdocMimeTypeFromZip(String path) {
    logger.debug("Get mime type from zip for " + path);
    String mimeType;
    try {
      ZipFile zipFile = new ZipFile(path);
      ZipEntry entry = zipFile.getEntry("mimetype");
      if (entry == null) {
        logger.error("Unsupported format, mimetype missing");
        throw new UnsupportedFormatException("Not an asic-e document. Mimetype is missing.");
      }
      InputStream stream = zipFile.getInputStream(entry);
      mimeType = IOUtils.toString(stream);
      stream.close();
      zipFile.close();
    } catch (IOException e) {
      e.printStackTrace();
      throw new DigiDoc4JException(e);
    }

    logger.debug("Mime type " + mimeType);
    return mimeType;
  }

  private void readsOpenedDocumentDetails() {
    logger.debug("");

    SignedDocumentValidator validator = ASiCContainerValidator.fromDocument(signedDocument);

    loadSignatures(validator);
    loadAttachments(validator);

    //TODO must be changed when extending signature is possible in sd-dss currently is possible to extend whole
    //container and it extend also all signatures
    setSignatureProfile(getSignatures().size() != 0 ? getSignature(0).getProfile() : LT);
    eu.europa.ec.markt.dss.DigestAlgorithm digestAlgorithm = dssSignatureParameters.getDigestAlgorithm();
    if (digestAlgorithm != null) {
      signatureParameters.setDigestAlgorithm(DigestAlgorithm.valueOf(digestAlgorithm.getName()));
    } else {
      signatureParameters.setDigestAlgorithm(null);
    }

    logger.debug("New BDoc container created");
  }

  private void loadAttachments(SignedDocumentValidator validator) {
    logger.debug("");
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
      if (simpleReport.getSignatureIdList().size() > 0)
        simpleReports.put(simpleReport.getSignatureIdList().get(0), simpleReport);
      report = report.getNextReports();
    } while (report != null);
    return simpleReports;
  }

  private void loadSignatures(SignedDocumentValidator validator) {
    logger.debug("");
    Map<String, SimpleReport> simpleReports = loadValidationResults(validator);
    List<AdvancedSignature> signatureList = validator.getSignatures();

    additionalVerificationErrors = new HashMap<>();
    for (AdvancedSignature advancedSignature : signatureList) {
      List<DigiDoc4JException> validationErrors = new ArrayList<>();
      String reportSignatureId = advancedSignature.getId();
      additionalVerificationErrors.put(reportSignatureId, validatePolicy(advancedSignature));
      DigiDoc4JException referenceError = validateSignedPropertiesReference(advancedSignature);
      if (referenceError != null)
        additionalVerificationErrors.get(reportSignatureId).add(referenceError);
      SimpleReport simpleReport = getSimpleReport(simpleReports, reportSignatureId);
      if (simpleReport != null) {
        for (Conclusion.BasicInfo error : simpleReport.getErrors(reportSignatureId)) {
          String errorMessage = error.toString();
          logger.info(errorMessage);
          if(errorMessage.contains(MessageTag.BBB_XCV_ISCR_ANS.getMessage()))
            validationErrors.add(new CertificateRevokedException(errorMessage));
          else
            validationErrors.add(new DigiDoc4JException(errorMessage));
        }
      }
      validationErrors.addAll(additionalVerificationErrors.get(reportSignatureId));
      signatures.add(new BDocSignature((XAdESSignature) advancedSignature, validationErrors));
    }
  }

  private DigiDoc4JException validateSignedPropertiesReference(AdvancedSignature advancedSignature) {
    logger.debug("");
    List<Element> signatureReferences = ((XAdESSignature) advancedSignature).getSignatureReferences();
    int nrOfSignedPropertiesReferences = 0;
    for (Element signatureReference : signatureReferences) {
      if (XADES_SIGNED_PROPERTIES.equals(signatureReference.getAttribute("Type")))
        nrOfSignedPropertiesReferences++;
    }
    if (nrOfSignedPropertiesReferences == 1) return null;
    String errorMessage;
    errorMessage = nrOfSignedPropertiesReferences == 0 ?  "Signed properties missing" : "Multiple signed properties";
    logger.info(errorMessage);
    return (new DigiDoc4JException(errorMessage));
  }

  private List<DigiDoc4JException> validatePolicy(AdvancedSignature advancedSignature) {
    logger.debug("");
    ArrayList<DigiDoc4JException> validationErrors = new ArrayList<>();
    SignaturePolicy policy = advancedSignature.getPolicyId();
    if (policy != null) {
      String policyIdentifier = policy.getIdentifier().trim();
      if (!TM_POLICY.equals(policyIdentifier)) {
        validationErrors.add(new DigiDoc4JException("Wrong policy identifier: " + policyIdentifier));
        return validationErrors;
      }
      if (isBlank(policy.getUrl()))
        validationErrors.add(new DigiDoc4JException("Policy url is missing for identifier: " + policyIdentifier));

      XPathQueryHolder xPathQueryHolder = ((XAdESSignature) advancedSignature).getXPathQueryHolder();
      Element signatureElement = ((XAdESSignature) advancedSignature).getSignatureElement();
      Element element = DSSXMLUtils.getElement(signatureElement, xPathQueryHolder.XPATH_SIGNATURE_POLICY_IDENTIFIER);
      Element identifier = DSSXMLUtils.getElement(element,
          "./xades:SignaturePolicyId/xades:SigPolicyId/xades:Identifier");
      if (!OIDAS_URN.equals(identifier.getAttribute("Qualifier"))) {
        validationErrors.add(new DigiDoc4JException("Wrong policy identifier qualifier: "
            + identifier.getAttribute("Qualifier")));
      }
    }

    return validationErrors;
  }

  private SimpleReport getSimpleReport(Map<String, SimpleReport> simpleReports, String fromSignatureId) {
    logger.debug("signature id : " + fromSignatureId);
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

    verifyIfAllowedToAddDataFile(path);

    validationReport = null;
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

  private void verifyIfAllowedToAddDataFile(String path) {
    if (signatures.size() > 0) {
      String errorMessage = "Datafiles cannot be added to an already signed container";
      logger.error(errorMessage);
      throw new DigiDoc4JException(errorMessage);
    }

    checkForDuplicateDataFile(path);
  }

  private void checkForDuplicateDataFile(String path) {
    logger.debug("");
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

    verifyIfAllowedToAddDataFile(fileName);

    validationReport = null;
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
    validationReport = null;
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

    validationReport = null;
    signatures.remove(index);
  }

  private DSSDocument createBareDocument(DSSDocument signature) {
    logger.debug("");
    if (signature.getName() == null) return signature;
    Document root = DSSXMLUtils.buildDOM(signature);
    final Element signatureEl = (Element) root.getDocumentElement().getFirstChild();
    return new InMemoryDocument(DSSXMLUtils.serializeNode(signatureEl));
  }

  private String getSignatureFileName(DSSDocument signature) {
    logger.debug("");
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
    logger.debug("");
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
    validationReport = null;
    return signRaw(signature);
  }

  private byte[] getDataToSign(String setSignatureId, X509Certificate signerCertificate) {
    logger.debug("");
    if (isTimeMark)
      addSignaturePolicy();

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

    SKOnlineOCSPSource ocspSource = getOcspSource(rawSignature);
    commonCertificateVerifier.setTrustedCertSource(configuration.getTSL());
    String userAgent = Helper.createUserAgent(this);
    ocspSource.setUserAgent(userAgent);

    commonCertificateVerifier.setOcspSource(ocspSource);
    OnlineTSPSource tspSource = new OnlineTSPSource(getConfiguration().getTspSource());
    tspSource.setUserAgent(userAgent);
    asicService.setTspSource(tspSource);

    String deterministicId = getDssSignatureParameters().getDeterministicId();

    try {
      signedDocument = asicService.signDocument(getSigningDocument(), dssSignatureParameters, rawSignature);
    } catch (DSSException e) {
      logger.error(e.getMessage());
      if ("OCSP request failed".equals(e.getMessage()))
        throw new OCSPRequestFailedException(e);
      throw new DigiDoc4JException(e);
    }

    XAdESSignature xAdESSignature = getSignatureById(deterministicId);

    validationReport = null;
    Signature signature = new BDocSignature(xAdESSignature);
    signatures.add(signature);

    return signature;
  }

  private SKOnlineOCSPSource getOcspSource(byte[] signatureValue) {
    logger.debug("");
    if (isTimeMark && signatureValue != null)
      return new BDocTMOcspSource(configuration, signatureValue);
    return new BDocTSOcspSource(configuration);
  }

  private DSSDocument getSigningDocument() {
    logger.debug("");
    if (signedDocument == null) {
      signedDocument = getAttachment();
    }
    return signedDocument;
  }

  private DSSDocument getAttachment() {
    logger.debug("");
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
    logger.debug("");

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

    Reports report = validate(validator);

    if ((signatures.size() > 0) && (((BDocSignature) signatures.get(0)).getOrigin().getReferences() == null)) {
      signatures = new ArrayList<>();
      loadSignatures(validator);
    }
    List<String> manifestErrors = new ManifestValidator(validator).validateDocument(signatures);
    return new ValidationResultForBDoc(report, signatures, manifestErrors, additionalVerificationErrors);
  }

  private Reports validate(SignedDocumentValidator validator) {
    logger.debug("Validator: " + validator);
    if (validationReport != null) {
      return validationReport;
    }

    commonCertificateVerifier.setOcspSource(null);

    TrustedListsCertificateSource trustedCertSource = configuration.getTSL();

    commonCertificateVerifier.setTrustedCertSource(trustedCertSource);
    validator.setCertificateVerifier(commonCertificateVerifier);

    try {
      validationReport = validator.validateDocument(getValidationPolicyAsStream(getConfiguration()
          .getValidationPolicy()));
      return validationReport;
    } catch (DSSException e) {
      logger.error(e.getMessage());
      throw new DigiDoc4JException(e);
    }
  }

  private InputStream getValidationPolicyAsStream(String policyFile) {
    logger.debug("");
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
    logger.debug("Get signature for index " + index);
    return getSignatures().get(index);
  }

  @Override
  public DocumentType getDocumentType() {
    logger.debug("");
    return DocumentType.BDOC;
  }

  @Override
  public ValidationResult validate() {
    logger.debug("");
    return verify();
  }

  private void extend(SignatureLevel signatureLevel) {
    logger.debug("");
    if (signatureLevel == dssSignatureParameters.getSignatureLevel()) {
      String errorMessage = "It is not possible to extend the signature to the same level";
      logger.error(errorMessage);
      throw new DigiDoc4JException(errorMessage);
    }
    SKOnlineOCSPSource ocspSource = getOcspSource(null);
    commonCertificateVerifier.setTrustedCertSource(configuration.getTSL());
    String userAgent = Helper.createUserAgent(this);
    ocspSource.setUserAgent(userAgent);
    commonCertificateVerifier.setOcspSource(ocspSource);
    OnlineTSPSource tspSource = new OnlineTSPSource(getConfiguration().getTspSource());
    tspSource.setUserAgent(userAgent);
    asicService.setTspSource(tspSource);

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
    logger.debug("");
    validationReport = null;
    isTimeMark = false;
    switch (profile) {
      case LT:
        extend(ASiC_E_BASELINE_LT);
        break;
      case LTA:
        extend(ASiC_E_BASELINE_LTA);
        break;
      case LT_TM:
        SignatureLevel currentSignatureLevel = dssSignatureParameters.getSignatureLevel();
        if (ASiC_E_BASELINE_LT.equals(currentSignatureLevel) || ASiC_E_BASELINE_LTA.equals(currentSignatureLevel) ||
            ASiC_E_BASELINE_B.equals(currentSignatureLevel)) {
          throw new DigiDoc4JException("It is not possible to extend the signature from " + currentSignatureLevel +
              " to LT_TM");
        }
        isTimeMark = true;
        extend(ASiC_E_BASELINE_LT);
        break;
      default:
        throw new NotYetImplementedException();
    }
  }

  @Override
  public void setSignatureProfile(SignatureProfile profile) {
    logger.debug("");
    isTimeMark = false;
    switch (profile) {
      case B_BES:
        dssSignatureParameters.setSignatureLevel(ASiC_E_BASELINE_B);
        break;
      case LTA:
        dssSignatureParameters.setSignatureLevel(ASiC_E_BASELINE_LTA);
        break;
      case LT_TM:
        isTimeMark = true;
      default:
        dssSignatureParameters.setSignatureLevel(ASiC_E_BASELINE_LT);
    }
  }

  protected eu.europa.ec.markt.dss.parameter.SignatureParameters getDssSignatureParameters() {
    logger.debug("");
    return dssSignatureParameters;
  }

  public void addDataFile(DataFile dataFile) {
    checkForDuplicateDataFile(dataFile.getName());
    dataFiles.put(dataFile.getName(), dataFile);
  }
}
