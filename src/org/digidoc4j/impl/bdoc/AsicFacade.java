/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc;

import static eu.europa.ec.markt.dss.DigestAlgorithm.SHA256;
import static eu.europa.ec.markt.dss.DigestAlgorithm.forName;
import static eu.europa.ec.markt.dss.signature.SignatureLevel.ASiC_E_BASELINE_B;
import static eu.europa.ec.markt.dss.signature.SignatureLevel.ASiC_E_BASELINE_LT;
import static eu.europa.ec.markt.dss.signature.SignatureLevel.ASiC_E_BASELINE_LTA;
import static eu.europa.ec.markt.dss.signature.SignaturePackaging.DETACHED;
import static eu.europa.ec.markt.dss.validation102853.SignatureForm.XAdES;
import static java.util.Arrays.asList;
import static org.apache.commons.codec.binary.Base64.decodeBase64;
import static org.apache.commons.lang.StringUtils.isEmpty;
import static org.digidoc4j.SignatureProfile.LT;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import org.apache.commons.io.IOUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.DataFile;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.EncryptionAlgorithm;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureParameters;
import org.digidoc4j.SignatureProductionPlace;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.SignatureToken;
import org.digidoc4j.SignedInfo;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.DuplicateDataFileException;
import org.digidoc4j.exceptions.NotYetImplementedException;
import org.digidoc4j.exceptions.OCSPRequestFailedException;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.exceptions.UnsupportedFormatException;
import org.digidoc4j.impl.SignatureFinalizer;
import org.digidoc4j.utils.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.parameter.BLevelParameters;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.DocumentSignatureService;
import eu.europa.ec.markt.dss.signature.FileDocument;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.MimeType;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.signature.StreamDocument;
import eu.europa.ec.markt.dss.signature.asic.ASiCService;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;
import eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.asic.ASiCXMLDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.ocsp.BDocTMOcspSource;
import eu.europa.ec.markt.dss.validation102853.ocsp.BDocTSOcspSource;
import eu.europa.ec.markt.dss.validation102853.ocsp.SKOnlineOCSPSource;
import eu.europa.ec.markt.dss.validation102853.report.Reports;
import eu.europa.ec.markt.dss.validation102853.tsp.OnlineTSPSource;
import eu.europa.ec.markt.dss.validation102853.xades.XAdESSignature;

/**
 * BDOC container implementation
 */
public class AsicFacade implements SignatureFinalizer, Serializable {

  private static final Logger logger = LoggerFactory.getLogger(AsicFacade.class);
  private static final int ONE_MB_IN_BYTES = 1048576;

  private final Map<String, DataFile> dataFiles = new LinkedHashMap<>();
  private SKCommonCertificateVerifier commonCertificateVerifier;
  private DocumentSignatureService asicService;
  private eu.europa.ec.markt.dss.parameter.SignatureParameters dssSignatureParameters;
  private SignatureParameters signatureParameters = new SignatureParameters();
  private DSSDocument signedDocument;
  private List<Signature> signatures = new ArrayList<>();
  protected Configuration configuration = null;
  private static final MimeType BDOC_MIME_TYPE = MimeType.ASICE;
  private transient Reports validationReport;
  private boolean isTimeMark = false;
  private Integer currentUsedSignatureFileIndex;
  private String userAgent;

  /**
   * Create a new container object of type BDOC.
   */
  public AsicFacade() {
    logger.debug("");
    this.configuration = new Configuration();
    initASiC();

    logger.info("New BDoc container created");
  }

  public SignedInfo prepareSigning(X509Certificate signerCert) {
    logger.debug("");
    String signatureId = signatureParameters.getSignatureId();
    byte[] bytesToSign = getDataToSign(signatureId != null ? signatureId : "S" + getSignatures().size(), signerCert);

    SignedInfo signedInfo = new SignedInfo(bytesToSign, signatureParameters);
    return signedInfo;
  }

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
  public AsicFacade(Configuration configuration) {
    logger.debug("");
    configuration.getTSL();
    this.configuration = configuration.copy();
    initASiC();
    logger.info("New BDoc container created");
  }


  public void setSignatureParameters(SignatureParameters signatureParameters) {
    logger.debug("");
    this.signatureParameters = signatureParameters.copy();

    setDigestAlgorithm();

    setEncryptionAlgorithm();
    addSignerInformation();
    addSignatureProfile(signatureParameters);
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

  public DigestAlgorithm getDigestAlgorithm() {
    DigestAlgorithm digestAlgorithm = signatureParameters.getDigestAlgorithm();
    logger.debug("");
    return digestAlgorithm;
  }

  private void initASiC() {
    logger.debug("");
    userAgent = Helper.createBDocUserAgent();
    dssSignatureParameters = new eu.europa.ec.markt.dss.parameter.SignatureParameters();
    dssSignatureParameters.setSignatureLevel(ASiC_E_BASELINE_LT);
    dssSignatureParameters.setSignaturePackaging(DETACHED);
    dssSignatureParameters.setDigestAlgorithm(SHA256);
    signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
    dssSignatureParameters.aSiC().setUnderlyingForm(XAdES);
    dssSignatureParameters.aSiC().setZipComment(userAgent);
    dssSignatureParameters.bLevel().setSigningCertificateDigestMethod(eu.europa.ec.markt.dss.DigestAlgorithm.SHA256);
    //dssSignatureParameters.setSignedInfoCanonicalizationMethod(Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS);

    commonCertificateVerifier = new SKCommonCertificateVerifier();
    commonCertificateVerifier.setCrlSource(null);
    asicService = new ASiCService(commonCertificateVerifier);
    OnlineTSPSource tspSource = new OnlineTSPSource(configuration.getTspSource());
    tspSource.setUserAgent(userAgent);
    asicService.setTspSource(tspSource);
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
  public AsicFacade(String path) {
    this(path, new Configuration());
  }

  /**
   * Opens container from a stream
   *
   * @param stream                      stream to read container from
   * @param actAsBigFilesSupportEnabled acts as configuration parameter
   * @see org.digidoc4j.Configuration#isBigFilesSupportEnabled() returns true
   */
  public AsicFacade(InputStream stream, boolean actAsBigFilesSupportEnabled) {
    this(stream, actAsBigFilesSupportEnabled, new Configuration());
  }

  public AsicFacade(InputStream stream, boolean actAsBigFilesSupportEnabled, Configuration configuration) {
    logger.info("Opening BDoc container from stream");
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
  public AsicFacade(String path, Configuration configuration) {
    logger.info("Opening BDoc container from file: " + path);
    configuration.getTSL();
    this.configuration = configuration.copy();
    initASiC();

    try {
      signedDocument = new FileDocument(path);
      signedDocument.setMimeType(MimeType.ASICE);
      checkMimeType(path);
    } catch (DSSException e) {
      logger.error(e.getMessage());
      throw new DigiDoc4JException(e);
    }

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

    AsicContainerValidationResult validationResult = new AsicContainerValidator(signedDocument, commonCertificateVerifier, configuration).loadContainerDetails();
    validationReport = validationResult.getValidationReport();
    dssSignatureParameters.setDigestAlgorithm(validationResult.getContainerDigestAlgorithm());
    signatures = validationResult.getSignatures();

    loadAttachments(validationResult.getSignedDocuments());

    //TODO must be changed when extending signature is possible in sd-dss currently is possible to extend whole
    //container and it extend also all signatures
    setSignatureProfile(getSignatures().size() != 0 ? getSignature(0).getProfile() : LT);
    eu.europa.ec.markt.dss.DigestAlgorithm digestAlgorithm = dssSignatureParameters.getDigestAlgorithm();
    if (digestAlgorithm != null) {
      signatureParameters.setDigestAlgorithm(DigestAlgorithm.valueOf(digestAlgorithm.getName()));
    } else {
      signatureParameters.setDigestAlgorithm(null);
    }

    currentUsedSignatureFileIndex = new AsicContainerParser(signedDocument).findCurrentSignatureFileIndex();

    logger.info("Finished reading BDoc container details");
  }

  private void loadAttachments(List<DSSDocument> signedDocuments) {
    logger.debug("");
    for (DSSDocument externalContent : signedDocuments) {
      if (!"mimetype".equals(externalContent.getName()) && !"META-INF/manifest.xml".equals(externalContent.getName())) {
        checkForDuplicateDataFile(externalContent.getName());
        dataFiles.put(externalContent.getName(), new DataFile(externalContent.getBytes(), externalContent.getName(),
            externalContent.getMimeType().getMimeTypeString()));
      }
    }
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

  public DataFile addDataFile(String path, String mimeType) {
    logger.info("Adding data file: " + path + ", mime type: " + mimeType);

    verifyIfAllowedToAddDataFile(path);

    validationReport = null;
    try {
      long cachedFileSizeInBytes = configuration.getMaxDataFileCachedInBytes();
      if (configuration.isBigFilesSupportEnabled() && new File(path).length() > cachedFileSizeInBytes) {
        DataFile dataFile = new DataFile(path, mimeType);
        dataFiles.put(path, dataFile);
        return dataFile;
      } else {
        InputStream is = Files.newInputStream(Paths.get(path));
        DataFile dataFile = new DataFile(IOUtils.toByteArray(is), path, mimeType);
        dataFiles.put(path, dataFile);
        is.close();
        return dataFile;
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
        throw new DuplicateDataFileException(errorMessage);
      }
    }
  }

  public DataFile addDataFile(InputStream is, String fileName, String mimeType) {
    logger.info("Adding data file: " + fileName + ", mime type: " + mimeType);

    verifyIfAllowedToAddDataFile(fileName);

    validationReport = null;
    try {
      if (configuration.isBigFilesSupportEnabled()) {
        DataFile dataFile = new DataFile(is, fileName, mimeType);
        dataFiles.put(fileName, dataFile);
        return dataFile;
      } else {
        DataFile dataFile = new DataFile(IOUtils.toByteArray(is), fileName, mimeType);
        dataFiles.put(fileName, dataFile);
        return dataFile;
      }
    } catch (IOException e) {
      logger.error(e.getMessage());
      throw new DigiDoc4JException(e);
    }
  }

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

  //TODO NotYetImplementedException
  public void addRawSignature(InputStream signatureStream) {
    logger.warn("Not yet implemented");
    throw new NotYetImplementedException();
  }

  public List<DataFile> getDataFiles() {
    logger.debug("");
    return new ArrayList<>(dataFiles.values());
  }

  @Deprecated
  public DataFile getDataFile(int index) {
    logger.debug("get data file with index: " + index);
    return getDataFiles().get(index);
  }

  public int countDataFiles() {
    return (dataFiles == null) ? 0 : dataFiles.size();
  }

  public void removeDataFile(String fileName) {
    logger.info("Removing data file: " + fileName);

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

  @Deprecated
  public void removeSignature(int index) {
    logger.info("Removing signature index: " + index);
    String signatureId = "S" + index;
    buildContainerWithoutSignature(signatureId);
    signatures.remove(index);
  }

  public void removeSignature(Signature signature) {
    logger.info("Removing signature " + signature.getId());
    buildContainerWithoutSignature(signature.getId());
    signatures.remove(signature);
  }

  private void buildContainerWithoutSignature(String signatureId) {
    SignedDocumentValidator validator = ASiCXMLDocumentValidator.fromDocument(signedDocument);
    DSSDocument signingDocument = getAttachment();
    DSSDocument signature = validator.removeSignature(signatureId);
    dssSignatureParameters.setDetachedContent(signingDocument);

    signedDocument = null;
    do {
      try {
        String signatureFileName = getSignatureFileName(signature);
        dssSignatureParameters.aSiC().setSignatureFileName(signatureFileName);
        signedDocument = ((ASiCService) asicService).buildASiCContainer(signingDocument, signedDocument,
            dssSignatureParameters, createBareDocument(signature));
        signature = signature.getNextDocument();
      } catch (IOException e) {
        logger.error("Error building asic container: " + e.getMessage());
        throw new TechnicalException("Error building asic container", e);
      }
    } while (signature != null);

    validationReport = null;
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

  public void save(String path) {
    logger.info("Saving container to file: " + path);
    documentMustBeInitializedCheck();
    try {
      signedDocument.save(path);
    } catch (IOException e) {
      logger.error("Error saving path: " + e.getMessage());
      throw new TechnicalException("Error saving path " + path, e);
    }
  }

  public void save(OutputStream out) {
    logger.info("Saving container to outputstream");
    try {
      IOUtils.copyLarge(signedDocument.openStream(), out);
    } catch (IOException e) {
      logger.error(e.getMessage());
      throw new DigiDoc4JException(e);
    }
  }

  public InputStream saveAsStream() {
    logger.info("Saving container as stream");
    return signedDocument.openStream();
  }

  //TODO NotYetImplementedException
  private void documentMustBeInitializedCheck() {
    logger.debug("");
    if (signedDocument == null) {
      logger.warn("Not yet implemented");
      throw new NotYetImplementedException();
    }
  }

  /**
   * Use <code>invokeSigning</code> method instead.
   * Method preserved for backwards compatibility. Adds signature to the container after signing.
   */
  @Deprecated
  public Signature sign(SignatureToken signatureToken) {
    Signature signature = invokeSigning(signatureToken);
    logger.debug("Adding signature to the signatures list");
    signatures.add(signature);
    return signature;
  }

  public Signature invokeSigning(SignatureToken signatureToken) {
    logger.info("Signing BDoc container");
    byte[] dataToSign;
    String signatureId = signatureParameters.getSignatureId();
    dataToSign = getDataToSign(signatureId != null ? signatureId : "S" + getSignatures().size(),
        signatureToken.getCertificate());

    byte[] signature = signatureToken.sign(getDigestAlgorithm(), dataToSign);
    validationReport = null;
    return finalizeSignature(signature);
  }

  private byte[] getDataToSign(String setSignatureId, X509Certificate signerCertificate) {
    logger.info("Getting data to sign");
    if (isTimeMark)
      addSignaturePolicy();

    dssSignatureParameters.clearCertificateChain();
    dssSignatureParameters.setDeterministicId(setSignatureId);
    dssSignatureParameters.aSiC().setSignatureFileName(calculateNextSignatureFileName());
    dssSignatureParameters.setSigningCertificate(new CertificateToken(signerCertificate));

    DSSDocument attachment = getAttachment();
    dssSignatureParameters.setDetachedContent(attachment);

    return asicService.getDataToSign(attachment, dssSignatureParameters);
  }

  @Override
  public Signature finalizeSignature(byte[] signatureValue) {
    logger.info("Finalizing BDoc signature");

    SKOnlineOCSPSource ocspSource = getOcspSource(signatureValue);
    commonCertificateVerifier.setTrustedCertSource(configuration.getTSL());
    ocspSource.setUserAgent(userAgent);
    commonCertificateVerifier.setOcspSource(ocspSource);

    String deterministicId = getDssSignatureParameters().getDeterministicId();

    try {
      signedDocument = asicService.signDocument(getSigningDocument(), dssSignatureParameters, signatureValue);
    } catch (DSSException e) {
      logger.error(e.getMessage());
      if ("OCSP request failed".equals(e.getMessage()))
        throw new OCSPRequestFailedException(e);
      throw new DigiDoc4JException(e);
    }

    XAdESSignature xAdESSignature = new AsicContainerValidator(signedDocument, commonCertificateVerifier, configuration).findXadesSignature(deterministicId);

    validationReport = null;
    Signature signature = new BDocSignature(xAdESSignature);

    logger.info("Signing BDoc successfully completed");
    return signature;
  }

  /**
   * Use <code>finalizeSignature</code> method instead.
   * Method preserved for backwards compatibility. Adds signature to the container after signing.
   */
  @Deprecated
  public Signature signRaw(byte[] rawSignature) {
    Signature signature = finalizeSignature(rawSignature);
    logger.debug("Adding signature to the signatures list");
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

    if (dataFiles.size() == 0) {
      String errorMessage = "Container does not contain any attachments";
      logger.error(errorMessage);
      throw new DigiDoc4JException(errorMessage);
    }
    Iterator<String> iterator = dataFiles.keySet().iterator();
    DSSDocument firstAttachment = getDssDocumentFromDataFile(dataFiles.get(iterator.next()));
    DSSDocument lastAttachment = firstAttachment;
    while (iterator.hasNext()) {
      String fileName = iterator.next();
      DSSDocument newAttachment = getDssDocumentFromDataFile(dataFiles.get(fileName));
      lastAttachment.setNextDocument(newAttachment);
      lastAttachment = newAttachment;
    }

    return firstAttachment;
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

  public Configuration getConfiguration() {
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

      BLevelParameters.SignerLocation signerLocation = new BLevelParameters.SignerLocation();

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
    logger.info("Verifying BDoc container");
    documentMustBeInitializedCheck();

    AsicContainerValidationResult result = new AsicContainerValidator(signedDocument, commonCertificateVerifier, configuration).validate();

    logger.info("BDoc container is valid: " + result.isValid());
    return result.getbDocValidationResult();
  }

  public List<Signature> getSignatures() {
    logger.debug("");
    return new ArrayList<>(signatures);
  }

  /**
   * @deprecated will be removed in the future.
   */
  @Deprecated
  public Signature getSignature(int index) {
    logger.debug("Get signature for index " + index);
    return getSignatures().get(index);
  }

  public void addSignature(Signature signature) {
    signatures.add(signature);
  }

  public int countSignatures() {
    return (signatures == null) ? 0 : signatures.size();
  }

  public Container.DocumentType getDocumentType() {
    logger.debug("");
    return Container.DocumentType.BDOC;
  }

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
    ocspSource.setUserAgent(userAgent);
    commonCertificateVerifier.setOcspSource(ocspSource);

    dssSignatureParameters.setSignatureLevel(signatureLevel);

    DSSDocument extendedDocument = asicService.extendDocument(signedDocument, dssSignatureParameters);
    signedDocument = new InMemoryDocument(extendedDocument.getBytes(),
        signedDocument.getName(), signedDocument.getMimeType());

    signatures = new AsicContainerValidator(signedDocument, commonCertificateVerifier, configuration).loadSignaturesWithoutValidation();
  }

  public String getVersion() {
    return null;
  }

  public void extendTo(SignatureProfile profile) {
    logger.info("Extending signature profile to " + profile.name());
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
    logger.info("Adding data file " + dataFile.getName());
    checkForDuplicateDataFile(dataFile.getName());
    dataFiles.put(dataFile.getName(), dataFile);
  }

  private void addSignatureProfile(SignatureParameters signatureParameters) {
    if(signatureParameters.getSignatureProfile() != null) {
      setSignatureProfile(signatureParameters.getSignatureProfile());
    }
  }

  private String calculateNextSignatureFileName() {
    if(currentUsedSignatureFileIndex == null) {
      currentUsedSignatureFileIndex = signatures.size() - 1;
    }
    currentUsedSignatureFileIndex++;
    return "signatures" + currentUsedSignatureFileIndex + ".xml";
  }
}
